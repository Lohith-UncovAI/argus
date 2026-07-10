#!/usr/bin/env python3

import csv
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

GRAPH = "https://graph.microsoft.com/v1.0"


def run_az(*args):
    result = subprocess.run(
        ["az", *args],
        text=True,
        capture_output=True,
        check=True
    )
    return result.stdout.strip()


def graph_token():
    raw = run_az(
        "account",
        "get-access-token",
        "--resource-type", "ms-graph",
        "-o", "json"
    )
    return json.loads(raw)["accessToken"]


TOKEN = graph_token()


def graph_get(url):
    if url.startswith("/"):
        url = GRAPH + url

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Graph returned HTTP {exc.code} for:\n{url}\n{body}"
        ) from exc


def graph_all(url):
    items = []

    while url:
        data = graph_get(url)
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    return items


def subtract_six_months(dt):
    year = dt.year
    month = dt.month - 6

    if month <= 0:
        month += 12
        year -= 1

    # Avoid failures for dates such as the 31st.
    days = [31, 29 if year % 4 == 0 and
            (year % 100 != 0 or year % 400 == 0) else 28,
            31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    day = min(dt.day, days[month - 1])
    return dt.replace(year=year, month=month, day=day)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


me = graph_get("/me?$select=id,displayName,mail,userPrincipalName,userType")
my_id = me["id"]
my_email = (me.get("mail") or me.get("userPrincipalName") or "").lower()

tenant = json.loads(run_az("account", "show", "-o", "json"))
my_tenant_id = tenant["tenantId"].lower()

now = datetime.now(timezone.utc)
start = subtract_six_months(now)

print(f"User:       {me.get('displayName')} <{my_email}>")
print(f"Period:     {iso(start)} to {iso(now)}")
print(f"Tenant ID:  {my_tenant_id}")
print("Reading calendar events...")

calendar_url = (
    f"{GRAPH}/me/calendarView"
    f"?startDateTime={urllib.parse.quote(iso(start))}"
    f"&endDateTime={urllib.parse.quote(iso(now))}"
    "&$select=id,subject,start,end,isOnlineMeeting,"
    "onlineMeeting,onlineMeetingProvider,organizer,type,isCancelled"
    "&$top=100"
)

events = graph_all(calendar_url)

organized_meetings = []
seen_join_urls = set()

for event in events:
    if event.get("isCancelled"):
        continue

    if not event.get("isOnlineMeeting"):
        continue

    provider = str(event.get("onlineMeetingProvider", "")).lower()
    if provider and provider != "teamsforbusiness":
        continue

    organizer_address = (
        event.get("organizer", {})
        .get("emailAddress", {})
        .get("address", "")
        .lower()
    )

    if organizer_address != my_email:
        continue

    join_url = (event.get("onlineMeeting") or {}).get("joinUrl")
    if not join_url:
        continue

    # Recurring calendar instances can point to the same meeting object.
    dedupe_key = (
        join_url,
        event.get("start", {}).get("dateTime")
    )
    if dedupe_key in seen_join_urls:
        continue

    seen_join_urls.add(dedupe_key)
    organized_meetings.append(event)

print(f"Organized Teams calendar meetings found: {len(organized_meetings)}")
print("Retrieving attendance records...")

user_cache = {}


def lookup_user(user_id):
    if not user_id:
        return None

    if user_id in user_cache:
        return user_cache[user_id]

    try:
        user = graph_get(
            f"/users/{urllib.parse.quote(user_id)}"
            "?$select=id,mail,userPrincipalName,userType"
        )
    except RuntimeError:
        user = None

    user_cache[user_id] = user
    return user


def classify_attendee(record):
    identity = record.get("identity") or {}
    user_identity = identity.get("user") or {}

    user_id = user_identity.get("id")
    tenant_id = str(user_identity.get("tenantId") or "").lower()
    email = str(record.get("emailAddress") or "").strip().lower()
    display_name = (
        user_identity.get("displayName")
        or record.get("emailAddress")
        or "Unknown"
    )

    # Do not count the organizer as an attendee category.
    if user_id == my_id or email == my_email:
        return "organizer", display_name, email

    directory_user = lookup_user(user_id)

    if directory_user:
        user_type = str(directory_user.get("userType") or "").lower()

        if user_type == "guest":
            return "tenant_guest", display_name, email

        if user_type == "member":
            return "internal_member", display_name, email

    if tenant_id and tenant_id == my_tenant_id:
        return "internal_member", display_name, email

    lowered_name = str(display_name).lower()

    if (
        "anonymous" in lowered_name
        or "unverified" in lowered_name
        or not user_id
    ):
        return "anonymous_or_unverified", display_name, email

    return "external_or_federated", display_name, email


rows = []
totals = Counter()
failed_meetings = 0

for number, event in enumerate(organized_meetings, start=1):
    subject = event.get("subject") or "(No subject)"
    start_time = event.get("start", {}).get("dateTime", "")
    join_url = event["onlineMeeting"]["joinUrl"]

    print(
        f"[{number}/{len(organized_meetings)}] "
        f"{start_time} — {subject}",
        file=sys.stderr
    )

    encoded_join_url = urllib.parse.quote(join_url, safe="")
    meeting_query = (
        f"{GRAPH}/me/onlineMeetings"
        f"?$filter=JoinWebUrl%20eq%20%27{encoded_join_url}%27"
    )

    try:
        meeting_matches = graph_all(meeting_query)

        if not meeting_matches:
            rows.append({
                "start": start_time,
                "subject": subject,
                "internal_members": 0,
                "tenant_guests": 0,
                "external_or_federated": 0,
                "anonymous_or_unverified": 0,
                "unique_non_organizer_attendees": 0,
                "has_external": "",
                "status": "onlineMeeting object not found"
            })
            failed_meetings += 1
            continue

        meeting_id = meeting_matches[0]["id"]

        reports = graph_all(
            f"{GRAPH}/me/onlineMeetings/"
            f"{urllib.parse.quote(meeting_id, safe='')}/attendanceReports"
        )

        if not reports:
            rows.append({
                "start": start_time,
                "subject": subject,
                "internal_members": 0,
                "tenant_guests": 0,
                "external_or_federated": 0,
                "anonymous_or_unverified": 0,
                "unique_non_organizer_attendees": 0,
                "has_external": "",
                "status": "No attendance report"
            })
            failed_meetings += 1
            continue

        # A recurring meeting can have multiple attendance reports.
        meeting_people = {}

        for report in reports:
            report_id = report["id"]
            records = graph_all(
                f"{GRAPH}/me/onlineMeetings/"
                f"{urllib.parse.quote(meeting_id, safe='')}"
                f"/attendanceReports/"
                f"{urllib.parse.quote(report_id, safe='')}"
                "/attendanceRecords"
            )

            for record in records:
                category, name, email = classify_attendee(record)

                if category == "organizer":
                    continue

                identity = record.get("identity") or {}
                attendee_id = (
                    (identity.get("user") or {}).get("id")
                    or email
                    or name
                )

                # Deduplicate someone who joined and left several times.
                meeting_people[attendee_id] = category

        counts = Counter(meeting_people.values())

        external_count = (
            counts["tenant_guest"]
            + counts["external_or_federated"]
            + counts["anonymous_or_unverified"]
        )

        rows.append({
            "start": start_time,
            "subject": subject,
            "internal_members": counts["internal_member"],
            "tenant_guests": counts["tenant_guest"],
            "external_or_federated": counts["external_or_federated"],
            "anonymous_or_unverified": counts["anonymous_or_unverified"],
            "unique_non_organizer_attendees": len(meeting_people),
            "has_external": "yes" if external_count else "no",
            "status": "OK"
        })

        totals["internal_members"] += counts["internal_member"]
        totals["tenant_guests"] += counts["tenant_guest"]
        totals["external_or_federated"] += counts[
            "external_or_federated"
        ]
        totals["anonymous_or_unverified"] += counts[
            "anonymous_or_unverified"
        ]
        totals["attendance_instances"] += len(meeting_people)

        if external_count:
            totals["meetings_with_external"] += 1
        else:
            totals["internal_only_meetings"] += 1

    except RuntimeError as exc:
        failed_meetings += 1
        rows.append({
            "start": start_time,
            "subject": subject,
            "internal_members": 0,
            "tenant_guests": 0,
            "external_or_federated": 0,
            "anonymous_or_unverified": 0,
            "unique_non_organizer_attendees": 0,
            "has_external": "",
            "status": str(exc).replace("\n", " ")[:500]
        })

output_file = "teams_meetings_last_6_months.csv"

fieldnames = [
    "start",
    "subject",
    "internal_members",
    "tenant_guests",
    "external_or_federated",
    "anonymous_or_unverified",
    "unique_non_organizer_attendees",
    "has_external",
    "status"
]

with open(output_file, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print()
print("=" * 62)
print("RESULTS")
print("=" * 62)
print(f"Organized Teams meetings:          {len(organized_meetings)}")
print(f"Meetings successfully analysed:    {len(organized_meetings) - failed_meetings}")
print(f"Meetings with external attendees:  {totals['meetings_with_external']}")
print(f"Internal-only meetings:            {totals['internal_only_meetings']}")
print(f"Meetings without usable report:    {failed_meetings}")
print()
print("Unique attendees are deduplicated within each meeting.")
print(f"Internal-member instances:         {totals['internal_members']}")
print(f"Tenant-guest instances:            {totals['tenant_guests']}")
print(f"External/federated instances:      {totals['external_or_federated']}")
print(f"Anonymous/unverified instances:    {totals['anonymous_or_unverified']}")
print(f"All attendee-meeting instances:    {totals['attendance_instances']}")
print()
print(f"Detailed CSV: {output_file}")
