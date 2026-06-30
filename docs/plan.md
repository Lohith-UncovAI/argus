/*
 *           _____       _____
 *      ,-'``_.-'` \   / `'-._``'-.
 *    ,`   .'      |`-'|      `.   `.
 *  ,`    (    /\  |   |  /\    )    `.
 * /       `--'  `-'   `-'  `--'       \
 * |                                   |
 * \      .--.  ,--.   ,--.  ,--.      /
 *  `.   (    \/ lt.\ /    \/    )   ,'
 *    `._ `--.___    V    ___.--' _,'
 *       `'----'`         `'----'`
 */




(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % argus-img scan ~/argus-eval-data/corpus/external/cyberseceval3/images/0.png --mode deep --profile HUMAN_VIEW
{
  "schema_version": "1.0.0",
  "scan_id": "scan-8e7ddcd2bcd6",
  "created_at": "2026-06-29T12:31:48.496771Z",
  "scanner": {
    "name": "argus-img",
    "version": "0.1.0",
    "offline_mode": true,
    "mode": "deep",
    "use_profile": "HUMAN_VIEW",
    "configuration_hash": "sha256:ec6c5cde5fd9244ebd02fe4994179e6d164b80e89b1a87948faee2f5564934a0"
  },
  "input": {
    "original_filename": "0.png",
    "size_bytes": 1349602,
    "sha256": "sha256:eedc0dff631e154cdf1ac2814449815ea4fdbea1b9583209eb71c5e1d793aa09",
    "declared_mime": null,
    "detected_mime": "image/png",
    "format": "PNG",
    "width": 1280,
    "height": 1110,
    "frames": 1,
    "quarantined_artifact_id": "artifact:scan-8e7ddcd2bcd6:original"
  },
  "decision": {
    "action": "REVIEW",
    "safe_claim": false,
    "reason_codes": [
      "PROMPT_INJECTION"
    ],
    "triggered_policy_rules": [
      "human-review-prompt"
    ],
    "winning_rule_id": "human-review-prompt",
    "winning_rule_priority": 700,
    "summary": "",
    "explanation": "Rule human-review-prompt matched finding finding:scan-8e7ddcd2bcd6:semantic:009."
  },
  "assessments": {
    "file_security": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "malware": {
      "state": "ERROR",
      "likelihood": null,
      "impact": "low",
      "coverage": "partial",
      "finding_ids": [],
      "limitations": [
        "detector:malware-clamav: ERROR",
        "detector:malware-yara: ERROR"
      ],
      "summary": "Assessment limited by detector coverage: ERROR."
    },
    "embedded_payload": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "prompt_injection": {
      "state": "HIGHLY_LIKELY",
      "likelihood": 0.75,
      "impact": "critical",
      "coverage": "medium",
      "finding_ids": [
        "finding:scan-8e7ddcd2bcd6:semantic:009"
      ],
      "limitations": [],
      "summary": "1 finding(s)"
    },
    "covert_channel": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Arbitrary encrypted steganography cannot be excluded."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "steganography": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Arbitrary encrypted steganography cannot be excluded."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "watermarks": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "Unknown watermark schemes are unsupported."
      ],
      "summary": "No evidence found in executed checks."
    },
    "provenance": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "phishing": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "privacy": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "redaction_failure": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "adversarial_instability": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Model-specific adversarial perturbations were not fully tested."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "authenticity_indicators": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    }
  },
  "findings": [
    {
      "finding_id": "finding:scan-8e7ddcd2bcd6:semantic:009",
      "category": "prompt_injection",
      "type": "semantic_injection",
      "state": "HIGHLY_LIKELY",
      "severity": "critical",
      "detector_confidence": 0.75,
      "evidence_quality": 0.7,
      "attack_likelihood": 0.75,
      "impact": "critical",
      "source_artifact_ids": [
        "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
        "artifact:scan-8e7ddcd2bcd6:blue-channel",
        "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
        "artifact:scan-8e7ddcd2bcd6:grayscale",
        "artifact:scan-8e7ddcd2bcd6:green-channel",
        "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
        "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
        "artifact:scan-8e7ddcd2bcd6:red-channel",
        "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "artifact:scan-8e7ddcd2bcd6:white-text-extract"
      ],
      "observation_ids": [
        "observation:scan-8e7ddcd2bcd6:ocr:000",
        "observation:scan-8e7ddcd2bcd6:ocr:001",
        "observation:scan-8e7ddcd2bcd6:ocr:004",
        "observation:scan-8e7ddcd2bcd6:ocr:005",
        "observation:scan-8e7ddcd2bcd6:ocr:006",
        "observation:scan-8e7ddcd2bcd6:ocr:007",
        "observation:scan-8e7ddcd2bcd6:ocr:008",
        "observation:scan-8e7ddcd2bcd6:ocr:009",
        "observation:scan-8e7ddcd2bcd6:ocr:010",
        "observation:scan-8e7ddcd2bcd6:ocr:011",
        "observation:scan-8e7ddcd2bcd6:ocr:012",
        "observation:scan-8e7ddcd2bcd6:ocr:016"
      ],
      "detector_ids": [
        "detector:semantic-scorer"
      ],
      "reason_codes": [
        "PROMPT_INJECTION"
      ],
      "recommended_action": "BLOCK",
      "limitations": [
        "No external ML model — score is heuristic, not probabilistic.",
        "Semantic scorer uses token/bigram heuristics; may produce false positives on security-education content quoting attack patterns."
      ],
      "evidence": {
        "semantic_score": 0.75,
        "matched_signal": "instead_secret",
        "signals": {
          "token_overlap": 0.30734126984126986,
          "bigram": 0.72,
          "structural": 0.75,
          "misleading_label": 0.0
        },
        "text_length": 93,
        "full_text_returned": false,
        "forensic_evidence_required": true
      }
    }
  ],
  "artifacts": {
    "original": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
      "sha256": "sha256:eedc0dff631e154cdf1ac2814449815ea4fdbea1b9583209eb71c5e1d793aa09",
      "media_type": "image/png",
      "size_bytes": 1349602,
      "created_by": "intake",
      "derived_from": null,
      "transformation": null,
      "storage_reference": "quarantine/ee/dc/eedc0dff631e154cdf1ac2814449815ea4fdbea1b9583209eb71c5e1d793aa09",
      "release_eligible": false,
      "role": "original",
      "width": null,
      "height": null,
      "frame_index": null,
      "representation_id": "repr:original"
    },
    "canonical_lossy": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
      "sha256": "sha256:de6e679d2872ac9798ec507b613567a750e1c2cbcee0d8f9c4c07aad79022c37",
      "media_type": "image/jpeg",
      "size_bytes": 258507,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:original",
      "transformation": {
        "transformation_id": "transform:canonical-lossy",
        "type": "canonical_lossy_jpeg",
        "parameters": {
          "metadata_stripped": true,
          "lossy": true,
          "flattened": true,
          "alpha_composited": true,
          "background": "white",
          "quality": 90
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/de/6e/de6e679d2872ac9798ec507b613567a750e1c2cbcee0d8f9c4c07aad79022c37",
      "release_eligible": false,
      "role": "canonical_lossy",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:release-candidate"
    },
    "canonical_lossless": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "sha256": "sha256:9dceb7856ad069bf8472bf7175599459ef14324bcdd8c1d643b3b4304b29e6ae",
      "media_type": "image/png",
      "size_bytes": 1351462,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:original",
      "transformation": {
        "transformation_id": "transform:canonical-lossless",
        "type": "canonical_lossless_png",
        "parameters": {
          "metadata_stripped": true,
          "orientation_applied": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/9d/ce/9dceb7856ad069bf8472bf7175599459ef14324bcdd8c1d643b3b4304b29e6ae",
      "release_eligible": false,
      "role": "canonical_lossless",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:canonical-lossless"
    },
    "flattened_white": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:flattened-white",
      "sha256": "sha256:0f620a7d8962aaf1ca2253d59e294357078778e8126c367da6d2054ec1949fec",
      "media_type": "image/png",
      "size_bytes": 1234233,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:original",
      "transformation": {
        "transformation_id": "transform:flattened-white",
        "type": "alpha_flatten",
        "parameters": {
          "background": "white",
          "metadata_stripped": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/0f/62/0f620a7d8962aaf1ca2253d59e294357078778e8126c367da6d2054ec1949fec",
      "release_eligible": false,
      "role": "flattened_white",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:alpha-white"
    },
    "flattened_black": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:flattened-black",
      "sha256": "sha256:0f620a7d8962aaf1ca2253d59e294357078778e8126c367da6d2054ec1949fec",
      "media_type": "image/png",
      "size_bytes": 1234233,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:original",
      "transformation": {
        "transformation_id": "transform:flattened-black",
        "type": "alpha_flatten",
        "parameters": {
          "background": "black",
          "metadata_stripped": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/0f/62/0f620a7d8962aaf1ca2253d59e294357078778e8126c367da6d2054ec1949fec",
      "release_eligible": false,
      "role": "flattened_black",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:alpha-black"
    },
    "grayscale": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:grayscale",
      "sha256": "sha256:df950e70517ccf49e6a8a199c5fc895c825546f53b261aacac5ab2664496e10a",
      "media_type": "image/png",
      "size_bytes": 765183,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:grayscale",
        "type": "grayscale",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/df/95/df950e70517ccf49e6a8a199c5fc895c825546f53b261aacac5ab2664496e10a",
      "release_eligible": false,
      "role": "grayscale",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:grayscale"
    },
    "otsu-threshold": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
      "sha256": "sha256:aecd45cf17dce771e7340ddfa79b129f64ba342f745921d586241704d642ff5f",
      "media_type": "image/png",
      "size_bytes": 55294,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:otsu-threshold",
        "type": "otsu_threshold",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/ae/cd/aecd45cf17dce771e7340ddfa79b129f64ba342f745921d586241704d642ff5f",
      "release_eligible": false,
      "role": "otsu-threshold",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:otsu-threshold"
    },
    "inverted-grayscale": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
      "sha256": "sha256:15377e013340ef2406b3e571418d4b4068b9087f006f3220750945e653be72cf",
      "media_type": "image/png",
      "size_bytes": 765101,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:inverted-grayscale",
        "type": "inverted_grayscale",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/15/37/15377e013340ef2406b3e571418d4b4068b9087f006f3220750945e653be72cf",
      "release_eligible": false,
      "role": "inverted-grayscale",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:inverted-grayscale"
    },
    "red-channel": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:red-channel",
      "sha256": "sha256:24c9d27712fb958fcec94333e910350f71bec7f072526021091aeab0f4cce7fd",
      "media_type": "image/png",
      "size_bytes": 782417,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:red-channel",
        "type": "red_channel",
        "parameters": {
          "source_channel": "red"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/24/c9/24c9d27712fb958fcec94333e910350f71bec7f072526021091aeab0f4cce7fd",
      "release_eligible": false,
      "role": "red-channel",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:red-channel"
    },
    "green-channel": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:green-channel",
      "sha256": "sha256:09bc5fcb6e1898cc3bdcea59eaeb0f2ee8fe6eda18167683d66adecfbe2188c5",
      "media_type": "image/png",
      "size_bytes": 773598,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:green-channel",
        "type": "green_channel",
        "parameters": {
          "source_channel": "green"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/09/bc/09bc5fcb6e1898cc3bdcea59eaeb0f2ee8fe6eda18167683d66adecfbe2188c5",
      "release_eligible": false,
      "role": "green-channel",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:green-channel"
    },
    "blue-channel": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:blue-channel",
      "sha256": "sha256:36be044ca8d3111b9b75c2b73568edbee1f89ea098a99f4451403d1803f408fd",
      "media_type": "image/png",
      "size_bytes": 785905,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:blue-channel",
        "type": "blue_channel",
        "parameters": {
          "source_channel": "blue"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/36/be/36be044ca8d3111b9b75c2b73568edbee1f89ea098a99f4451403d1803f408fd",
      "release_eligible": false,
      "role": "blue-channel",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:blue-channel"
    },
    "alpha-channel": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:alpha-channel",
      "sha256": "sha256:b580df05d0613ca6c1c3756e52bc0a015a9c41b509e00de654e97a0948f74e06",
      "media_type": "image/png",
      "size_bytes": 6609,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:alpha-channel",
        "type": "alpha_channel",
        "parameters": {
          "source_channel": "alpha"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/b5/80/b580df05d0613ca6c1c3756e52bc0a015a9c41b509e00de654e97a0948f74e06",
      "release_eligible": false,
      "role": "alpha-channel",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:alpha-channel"
    },
    "2x-enlargement": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
      "sha256": "sha256:eaa86ab7848a21add50dca514940f75a5b8b5bf6a39e434ea331fc62dcfaae3b",
      "media_type": "image/png",
      "size_bytes": 3745466,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:2x-enlargement",
        "type": "2x_enlargement",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/ea/a8/eaa86ab7848a21add50dca514940f75a5b8b5bf6a39e434ea331fc62dcfaae3b",
      "release_eligible": false,
      "role": "2x-enlargement",
      "width": 2560,
      "height": 2220,
      "frame_index": null,
      "representation_id": "repr:2x-enlargement"
    },
    "white-text-extract": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
      "sha256": "sha256:ff22d6c0535103cb1537dd27b22bbe576b41248a6445f47e1dac823f6996d0d9",
      "media_type": "image/png",
      "size_bytes": 20390,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:white-text-extract",
        "type": "white_text_extract",
        "parameters": {
          "method": "invert_threshold",
          "threshold": 60
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/ff/22/ff22d6c0535103cb1537dd27b22bbe576b41248a6445f47e1dac823f6996d0d9",
      "release_eligible": false,
      "role": "white-text-extract",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:white-text-extract"
    },
    "bg-normalised": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
      "sha256": "sha256:add3bc961c1a78c5cf324b8c425715438f28f8e2e3bf577de12272902dc73d1e",
      "media_type": "image/png",
      "size_bytes": 897357,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:bg-normalised",
        "type": "bg_normalised",
        "parameters": {
          "method": "background_divide",
          "radius": 25,
          "scale": 175
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/ad/d3/add3bc961c1a78c5cf324b8c425715438f28f8e2e3bf577de12272902dc73d1e",
      "release_eligible": false,
      "role": "bg-normalised",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:bg-normalised"
    },
    "sharpen-contrast": {
      "artifact_id": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
      "sha256": "sha256:2b68d6fe811baddbabc01512062af9a0c71746e128be75b679623fe87795d88d",
      "media_type": "image/png",
      "size_bytes": 704815,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:sharpen-contrast",
        "type": "sharpen_contrast",
        "parameters": {
          "sharpness": 2.0,
          "contrast": 3.0
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/2b/68/2b68d6fe811baddbabc01512062af9a0c71746e128be75b679623fe87795d88d",
      "release_eligible": false,
      "role": "sharpen-contrast",
      "width": 1280,
      "height": 1110,
      "frame_index": null,
      "representation_id": "repr:sharpen-contrast"
    }
  },
  "representation_manifest": {
    "entries": [
      {
        "representation_id": "repr:2x-enlargement",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:eaa86ab7848a21add50dca514940f75a5b8b5bf6a39e434ea331fc62dcfaae3b",
        "width": 2560,
        "height": 2220,
        "frame_index": null,
        "transformation_id": "transform:2x-enlargement",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-channel",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:alpha-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:b580df05d0613ca6c1c3756e52bc0a015a9c41b509e00de654e97a0948f74e06",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:alpha-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:bg-normalised",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:add3bc961c1a78c5cf324b8c425715438f28f8e2e3bf577de12272902dc73d1e",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:bg-normalised",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:blue-channel",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:blue-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:36be044ca8d3111b9b75c2b73568edbee1f89ea098a99f4451403d1803f408fd",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:blue-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:canonical-lossless",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "kind": "canonical_lossless",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:9dceb7856ad069bf8472bf7175599459ef14324bcdd8c1d643b3b4304b29e6ae",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:canonical-lossless",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:release-candidate",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
        "kind": "release_candidate",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/jpeg",
        "sha256": "sha256:de6e679d2872ac9798ec507b613567a750e1c2cbcee0d8f9c4c07aad79022c37",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:canonical-lossy",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-black",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:flattened-black",
        "kind": "alpha_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:0f620a7d8962aaf1ca2253d59e294357078778e8126c367da6d2054ec1949fec",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:flattened-black",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-white",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:flattened-white",
        "kind": "alpha_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:0f620a7d8962aaf1ca2253d59e294357078778e8126c367da6d2054ec1949fec",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:flattened-white",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:grayscale",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:grayscale",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:df950e70517ccf49e6a8a199c5fc895c825546f53b261aacac5ab2664496e10a",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:grayscale",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:green-channel",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:green-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:09bc5fcb6e1898cc3bdcea59eaeb0f2ee8fe6eda18167683d66adecfbe2188c5",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:green-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:inverted-grayscale",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:15377e013340ef2406b3e571418d4b4068b9087f006f3220750945e653be72cf",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:inverted-grayscale",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:original",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
        "kind": "original_container",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:eedc0dff631e154cdf1ac2814449815ea4fdbea1b9583209eb71c5e1d793aa09",
        "width": null,
        "height": null,
        "frame_index": null,
        "transformation_id": null,
        "coverage_notes": []
      },
      {
        "representation_id": "repr:otsu-threshold",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:aecd45cf17dce771e7340ddfa79b129f64ba342f745921d586241704d642ff5f",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:otsu-threshold",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:red-channel",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:red-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:24c9d27712fb958fcec94333e910350f71bec7f072526021091aeab0f4cce7fd",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:red-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:sharpen-contrast",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:2b68d6fe811baddbabc01512062af9a0c71746e128be75b679623fe87795d88d",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:sharpen-contrast",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:white-text-extract",
        "artifact_id": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:ff22d6c0535103cb1537dd27b22bbe576b41248a6445f47e1dac823f6996d0d9",
        "width": 1280,
        "height": 1110,
        "frame_index": null,
        "transformation_id": "transform:white-text-extract",
        "coverage_notes": []
      }
    ],
    "coverage_complete": true,
    "missing_required": []
  },
  "observations": [
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:000",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:canonical-lossy",
      "location": {
        "artifact_label": "release_candidate"
      },
      "sha256": "sha256:11040517baa519b52f3d07716d1dc744b85347f42d2401ede9758ac9de388790",
      "length": 68
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:001",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:canonical-lossless",
      "location": {
        "artifact_label": "canonical_lossless"
      },
      "sha256": "sha256:8d0840df1626c4a46d82c10d861e020da12beeebf494b45ac6dcce066c7db54d",
      "length": 85
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:002",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:flattened-white",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:flattened-white",
      "location": {
        "artifact_label": "flattened_white"
      },
      "sha256": "sha256:8d0840df1626c4a46d82c10d861e020da12beeebf494b45ac6dcce066c7db54d",
      "length": 85
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:003",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:flattened-black",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:flattened-black",
      "location": {
        "artifact_label": "flattened_black"
      },
      "sha256": "sha256:8d0840df1626c4a46d82c10d861e020da12beeebf494b45ac6dcce066c7db54d",
      "length": 85
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:004",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:grayscale",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:grayscale",
      "location": {
        "artifact_label": "grayscale"
      },
      "sha256": "sha256:469eb31a3d346f9e8133efc72af1636511db3b1a73579ae79c90359917ea1a86",
      "length": 143
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:005",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:otsu-threshold",
      "location": {
        "artifact_label": "otsu-threshold"
      },
      "sha256": "sha256:ed459a6b92be430b058431a12a9111e22a454f5729646559978c67c50d2573b9",
      "length": 164
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:006",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:inverted-grayscale",
      "location": {
        "artifact_label": "inverted-grayscale"
      },
      "sha256": "sha256:49bec0ec9503ff15c769a8369fa4491f51a20da8b171223968006562c246a2ec",
      "length": 147
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:007",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:red-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:red-channel",
      "location": {
        "artifact_label": "red-channel"
      },
      "sha256": "sha256:f68874cceaae7f4f6b3fb61700c22f8546f5718edabc420e84d430d5596f92f8",
      "length": 129
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:008",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:green-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:green-channel",
      "location": {
        "artifact_label": "green-channel"
      },
      "sha256": "sha256:847a05982ffdb35fbc39694f69d8da4a95691652b2bc60563569e71ef02b649c",
      "length": 175
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:009",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:blue-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:blue-channel",
      "location": {
        "artifact_label": "blue-channel"
      },
      "sha256": "sha256:9927b15819f7e3ae45f315b147afa53ba92a868d607dc9a5bbf8f4410eae8c17",
      "length": 86
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:010",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:2x-enlargement",
      "location": {
        "artifact_label": "2x-enlargement"
      },
      "sha256": "sha256:1ccb9a453304f2f933858bf4166d259ae78867a33c2ac58680a7d23e4572aa41",
      "length": 94
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:011",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:white-text-extract",
      "location": {
        "artifact_label": "white-text-extract"
      },
      "sha256": "sha256:178d7ee440109b8b0ecf428cae33e8191d91403c9666abfe105db2d22e50cace",
      "length": 98
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:012",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:white-text-extract",
      "location": {
        "artifact_label": "white-text-extract"
      },
      "sha256": "sha256:cb27305f45727536ddcda3807b6432481b6c18f776f217c4eae8fbd014a50e24",
      "length": 119
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:013",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:bg-normalised",
      "location": {
        "artifact_label": "bg-normalised"
      },
      "sha256": "sha256:8ee7b1c80482021c5e4133f97ad5ee6ec931614d040ad3092e8b2787de738100",
      "length": 129
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:014",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:bg-normalised",
      "location": {
        "artifact_label": "bg-normalised"
      },
      "sha256": "sha256:c7e90408bc34eb91845c548091dee035d22433af80d408cb05510b99489b4b0b",
      "length": 165
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:015",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:sharpen-contrast",
      "location": {
        "artifact_label": "sharpen-contrast"
      },
      "sha256": "sha256:b8a282122a0d40831d51897a131665a38d19ba43baac507551632646954bd76f",
      "length": 155
    },
    {
      "observation_id": "observation:scan-8e7ddcd2bcd6:ocr:016",
      "source_artifact_id": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:sharpen-contrast",
      "location": {
        "artifact_label": "sharpen-contrast"
      },
      "sha256": "sha256:07bcd14a94d5edf991586cfe233c90b410d402faaf972be74f067b948631d629",
      "length": 125
    }
  ],
  "detector_executions": [
    {
      "detector_id": "detector:metadata-builtin",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "metadata",
      "category": "privacy",
      "required": true,
      "started_at": "2026-06-29T12:31:42.527147Z",
      "completed_at": "2026-06-29T12:31:42.541473Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:exiftool",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "metadata",
      "category": "privacy",
      "required": false,
      "started_at": "2026-06-29T12:31:42.541503Z",
      "completed_at": "2026-06-29T12:31:42.628465Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": "13.55"
    },
    {
      "detector_id": "detector:malware-clamav",
      "status": "ERROR",
      "state": "ERROR",
      "family": "malware",
      "category": "malware",
      "required": false,
      "started_at": "2026-06-29T12:31:42.628685Z",
      "completed_at": "2026-06-29T12:31:42.658472Z",
      "duration_ms": 16.96174999960931,
      "reason": "signature_database_missing",
      "tool_version": "ClamAV 1.5.2"
    },
    {
      "detector_id": "detector:malware-yara",
      "status": "ERROR",
      "state": "ERROR",
      "family": "malware",
      "category": "malware",
      "required": false,
      "started_at": "2026-06-29T12:31:42.658584Z",
      "completed_at": "2026-06-29T12:31:42.658640Z",
      "duration_ms": null,
      "reason": "yara_rule_bundle_missing",
      "tool_version": null
    },
    {
      "detector_id": "detector:embedded-binwalk",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "embedded_payload",
      "category": "embedded_payload",
      "required": false,
      "started_at": "2026-06-29T12:31:42.658655Z",
      "completed_at": "2026-06-29T12:31:42.678765Z",
      "duration_ms": 9.170500001346227,
      "reason": null,
      "tool_version": "Analyzes data for embedded file types"
    },
    {
      "detector_id": "detector:tesseract",
      "status": "SUCCESS",
      "state": "CONFIRMED",
      "family": "OCR",
      "category": "prompt_injection",
      "required": false,
      "started_at": "2026-06-29T12:31:42.679255Z",
      "completed_at": "2026-06-29T12:31:46.216577Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": "tesseract 5.5.2"
    },
    {
      "detector_id": "detector:qr-pyzbar",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "QR/barcode",
      "category": "embedded_payload",
      "required": false,
      "started_at": "2026-06-29T12:31:48.473713Z",
      "completed_at": "2026-06-29T12:31:48.473713Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:prompt-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "prompt",
      "category": "prompt_injection",
      "required": true,
      "started_at": "2026-06-29T12:31:48.476779Z",
      "completed_at": "2026-06-29T12:31:48.479038Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:semantic-scorer",
      "status": "SUCCESS",
      "state": "CONFIRMED",
      "family": "prompt",
      "category": "prompt_injection",
      "required": false,
      "started_at": "2026-06-29T12:31:48.479045Z",
      "completed_at": "2026-06-29T12:31:48.480255Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:privacy-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "privacy",
      "category": "privacy",
      "required": false,
      "started_at": "2026-06-29T12:31:48.480259Z",
      "completed_at": "2026-06-29T12:31:48.480375Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:phishing-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "phishing",
      "category": "phishing",
      "required": false,
      "started_at": "2026-06-29T12:31:48.480377Z",
      "completed_at": "2026-06-29T12:31:48.480417Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:visible-watermark-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "watermarks",
      "category": "watermarks",
      "required": false,
      "started_at": "2026-06-29T12:31:48.480432Z",
      "completed_at": "2026-06-29T12:31:48.480432Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    }
  ],
  "release_grants": [],
  "coverage": {
    "original_container": "high",
    "all_frames": "complete",
    "visible_text": "medium",
    "low_contrast_text": "medium",
    "metadata_text": "medium",
    "known_embedded_formats": "low",
    "common_steganography": "low",
    "unknown_steganography": "low",
    "registered_watermark_schemes": "low",
    "unknown_watermarks": "unsupported",
    "model_specific_adversarial_attacks": "not_tested",
    "universal_attack_absence": "impossible",
    "universal_absence_claim": false
  },
  "module_status": {
    "artifact_store": {
      "name": "artifact_store",
      "status": "CONFIRMED",
      "reason": "/Users/lohith-uncovai/argus-eval-data/corpus/prompt_injection/data/argus.sqlite3",
      "version": null
    },
    "opencv_decoder": {
      "name": "opencv_decoder",
      "status": "CONFIRMED",
      "reason": null,
      "version": null
    },
    "release_candidate_decoder": {
      "name": "opencv_decoder",
      "status": "CONFIRMED",
      "reason": null,
      "version": null
    },
    "metadata_builtin": {
      "name": "metadata_builtin",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": null
    },
    "exiftool": {
      "name": "exiftool",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": "13.55"
    },
    "binwalk": {
      "name": "binwalk",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": "Analyzes data for embedded file types"
    },
    "clamav": {
      "name": "clamav",
      "status": "ERROR",
      "reason": "signature_database_missing",
      "version": "ClamAV 1.5.2"
    },
    "yara": {
      "name": "yara",
      "status": "ERROR",
      "reason": "yara_rule_bundle_missing",
      "version": null
    },
    "c2pa": {
      "name": "c2pa",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "paddleocr": {
      "name": "paddleocr",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "zsteg": {
      "name": "zsteg",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "embedded_thumbnails": {
      "name": "embedded_thumbnails",
      "status": "NO_EVIDENCE_FOUND",
      "reason": "no embedded thumbnails found",
      "version": null
    },
    "watermark_registry": {
      "name": "watermark_registry",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "redaction_analysis": {
      "name": "redaction_analysis",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "adversarial_stability": {
      "name": "adversarial_stability",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "visual_analyzer": {
      "name": "visual_analyzer",
      "status": "NOT_TESTED",
      "reason": "NullVisualAnalyzer configured",
      "version": null
    },
    "tesseract": {
      "name": "tesseract",
      "status": "CONFIRMED",
      "reason": null,
      "version": "tesseract 5.5.2"
    },
    "qr": {
      "name": "qr",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": null
    },
    "steganalysis_statistics": {
      "name": "steganalysis_statistics",
      "status": "CONFIRMED",
      "reason": "{'grayscale_entropy': 7.40230431854113}",
      "version": null
    }
  },
  "limitations": [
    {
      "limitation_id": "limitation:universal-safety",
      "category": "global",
      "description": "No report can prove an image is universally safe."
    },
    {
      "limitation_id": "limitation:unknown-steganography",
      "category": "steganography",
      "description": "Arbitrary encrypted steganography cannot be excluded."
    },
    {
      "limitation_id": "limitation:unknown-watermarks",
      "category": "watermarks",
      "description": "Unknown watermark schemes are not exhaustively detectable."
    }
  ],
  "errors": [],
  "timings_ms": {
    "total_ms": 7325.128875003429
  },
  "evidence_graph": {
    "nodes": [
      {
        "id": "artifact:scan-8e7ddcd2bcd6:original",
        "type": "Artifact",
        "role": "original"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
        "type": "Artifact",
        "role": "canonical_lossy"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "type": "Artifact",
        "role": "canonical_lossless"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:flattened-white",
        "type": "Artifact",
        "role": "flattened_white"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:flattened-black",
        "type": "Artifact",
        "role": "flattened_black"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:grayscale",
        "type": "Artifact",
        "role": "grayscale"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
        "type": "Artifact",
        "role": "otsu-threshold"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
        "type": "Artifact",
        "role": "inverted-grayscale"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:red-channel",
        "type": "Artifact",
        "role": "red-channel"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:green-channel",
        "type": "Artifact",
        "role": "green-channel"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:blue-channel",
        "type": "Artifact",
        "role": "blue-channel"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:alpha-channel",
        "type": "Artifact",
        "role": "alpha-channel"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
        "type": "Artifact",
        "role": "2x-enlargement"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
        "type": "Artifact",
        "role": "white-text-extract"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
        "type": "Artifact",
        "role": "bg-normalised"
      },
      {
        "id": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "type": "Artifact",
        "role": "sharpen-contrast"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:000",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:001",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:002",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:003",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:004",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:005",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:006",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:007",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:008",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:009",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:010",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:011",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:012",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:013",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:014",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:015",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-8e7ddcd2bcd6:ocr:016",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "Finding",
        "category": "prompt_injection"
      }
    ],
    "edges": [
      {
        "from": "artifact:scan-8e7ddcd2bcd6:original",
        "to": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
        "type": "derived_from",
        "transformation": "transform:canonical-lossy"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:original",
        "to": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "type": "derived_from",
        "transformation": "transform:canonical-lossless"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:original",
        "to": "artifact:scan-8e7ddcd2bcd6:flattened-white",
        "type": "derived_from",
        "transformation": "transform:flattened-white"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:original",
        "to": "artifact:scan-8e7ddcd2bcd6:flattened-black",
        "type": "derived_from",
        "transformation": "transform:flattened-black"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:grayscale",
        "type": "derived_from",
        "transformation": "transform:grayscale"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
        "type": "derived_from",
        "transformation": "transform:otsu-threshold"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
        "type": "derived_from",
        "transformation": "transform:inverted-grayscale"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:red-channel",
        "type": "derived_from",
        "transformation": "transform:red-channel"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:green-channel",
        "type": "derived_from",
        "transformation": "transform:green-channel"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:blue-channel",
        "type": "derived_from",
        "transformation": "transform:blue-channel"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:alpha-channel",
        "type": "derived_from",
        "transformation": "transform:alpha-channel"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
        "type": "derived_from",
        "transformation": "transform:2x-enlargement"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
        "type": "derived_from",
        "transformation": "transform:white-text-extract"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
        "type": "derived_from",
        "transformation": "transform:bg-normalised"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "type": "derived_from",
        "transformation": "transform:sharpen-contrast"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:000",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:001",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:flattened-white",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:002",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:flattened-black",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:003",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:grayscale",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:004",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:005",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:006",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:red-channel",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:007",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:green-channel",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:008",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:blue-channel",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:009",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:010",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:011",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:012",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:013",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:bg-normalised",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:014",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:015",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "to": "observation:scan-8e7ddcd2bcd6:ocr:016",
        "type": "observed_in"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:000",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:001",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:004",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:005",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:006",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:007",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:008",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:009",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:010",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:011",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:012",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "observation:scan-8e7ddcd2bcd6:ocr:016",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:2x-enlargement",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:blue-channel",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossless",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:canonical-lossy",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:grayscale",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:green-channel",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:inverted-grayscale",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:otsu-threshold",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:red-channel",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:sharpen-contrast",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      },
      {
        "from": "artifact:scan-8e7ddcd2bcd6:white-text-extract",
        "to": "finding:scan-8e7ddcd2bcd6:semantic:009",
        "type": "supports"
      }
    ]
  }
}
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 






(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % argus-img scan ~/argus-eval-data/corpus/alpha/alpha-low-alpha-text-001.png --mode deep --profile HUMAN_VIEW
{
  "schema_version": "1.0.0",
  "scan_id": "scan-f369b7813391",
  "created_at": "2026-06-29T12:34:29.476717Z",
  "scanner": {
    "name": "argus-img",
    "version": "0.1.0",
    "offline_mode": true,
    "mode": "deep",
    "use_profile": "HUMAN_VIEW",
    "configuration_hash": "sha256:ec6c5cde5fd9244ebd02fe4994179e6d164b80e89b1a87948faee2f5564934a0"
  },
  "input": {
    "original_filename": "alpha-low-alpha-text-001.png",
    "size_bytes": 4335,
    "sha256": "sha256:02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
    "declared_mime": null,
    "detected_mime": "image/png",
    "format": "PNG",
    "width": 640,
    "height": 240,
    "frames": 1,
    "quarantined_artifact_id": "artifact:scan-f369b7813391:original"
  },
  "decision": {
    "action": "ALLOW_WITH_REDACTION",
    "safe_claim": false,
    "reason_codes": [
      "EMAIL_ADDRESS"
    ],
    "triggered_policy_rules": [
      "human-redact-privacy"
    ],
    "winning_rule_id": "human-redact-privacy",
    "winning_rule_priority": 500,
    "summary": "",
    "explanation": "Rule human-redact-privacy matched finding finding:scan-f369b7813391:privacy:000."
  },
  "assessments": {
    "file_security": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "malware": {
      "state": "ERROR",
      "likelihood": null,
      "impact": "low",
      "coverage": "partial",
      "finding_ids": [],
      "limitations": [
        "detector:malware-clamav: ERROR",
        "detector:malware-yara: ERROR"
      ],
      "summary": "Assessment limited by detector coverage: ERROR."
    },
    "embedded_payload": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "prompt_injection": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "covert_channel": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Arbitrary encrypted steganography cannot be excluded."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "steganography": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Arbitrary encrypted steganography cannot be excluded."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "watermarks": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "Unknown watermark schemes are unsupported."
      ],
      "summary": "No evidence found in executed checks."
    },
    "provenance": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "phishing": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "privacy": {
      "state": "CONFIRMED",
      "likelihood": 0.0,
      "impact": "high",
      "coverage": "medium",
      "finding_ids": [
        "finding:scan-f369b7813391:privacy:000"
      ],
      "limitations": [],
      "summary": "1 finding(s)"
    },
    "redaction_failure": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "adversarial_instability": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Model-specific adversarial perturbations were not fully tested."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "authenticity_indicators": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    }
  },
  "findings": [
    {
      "finding_id": "finding:scan-f369b7813391:privacy:000",
      "category": "privacy",
      "type": "email_address",
      "state": "CONFIRMED",
      "severity": "medium",
      "detector_confidence": null,
      "evidence_quality": 0.8,
      "attack_likelihood": null,
      "impact": "high",
      "source_artifact_ids": [
        "artifact:scan-f369b7813391:sharpen-contrast"
      ],
      "observation_ids": [
        "observation:scan-f369b7813391:ocr:013"
      ],
      "detector_ids": [
        "detector:privacy-rules"
      ],
      "reason_codes": [
        "EMAIL_ADDRESS"
      ],
      "recommended_action": "ALLOW_WITH_REDACTION",
      "limitations": [],
      "evidence": {
        "text_sha256": "sha256:538e2ad4343a8c4be35b0f41165cd51959421d999e91039ead692de15c79d2f0",
        "text_length": 62,
        "full_text_returned": false,
        "forensic_evidence_required": true
      }
    }
  ],
  "artifacts": {
    "original": {
      "artifact_id": "artifact:scan-f369b7813391:original",
      "sha256": "sha256:02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
      "media_type": "image/png",
      "size_bytes": 4335,
      "created_by": "intake",
      "derived_from": null,
      "transformation": null,
      "storage_reference": "quarantine/02/e7/02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
      "release_eligible": false,
      "role": "original",
      "width": null,
      "height": null,
      "frame_index": null,
      "representation_id": "repr:original"
    },
    "canonical_lossy": {
      "artifact_id": "artifact:scan-f369b7813391:canonical-lossy",
      "sha256": "sha256:a9cb5d2ef47babdda154e042d9efa026b98d284c417a687cf365dc1025497923",
      "media_type": "image/jpeg",
      "size_bytes": 5992,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-f369b7813391:original",
      "transformation": {
        "transformation_id": "transform:canonical-lossy",
        "type": "canonical_lossy_jpeg",
        "parameters": {
          "metadata_stripped": true,
          "lossy": true,
          "flattened": true,
          "alpha_composited": true,
          "background": "white",
          "quality": 90
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a9/cb/a9cb5d2ef47babdda154e042d9efa026b98d284c417a687cf365dc1025497923",
      "release_eligible": false,
      "role": "canonical_lossy",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:release-candidate"
    },
    "canonical_lossless": {
      "artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
      "sha256": "sha256:02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
      "media_type": "image/png",
      "size_bytes": 4335,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-f369b7813391:original",
      "transformation": {
        "transformation_id": "transform:canonical-lossless",
        "type": "canonical_lossless_png",
        "parameters": {
          "metadata_stripped": true,
          "orientation_applied": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/02/e7/02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
      "release_eligible": false,
      "role": "canonical_lossless",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:canonical-lossless"
    },
    "flattened_white": {
      "artifact_id": "artifact:scan-f369b7813391:flattened-white",
      "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-f369b7813391:original",
      "transformation": {
        "transformation_id": "transform:flattened-white",
        "type": "alpha_flatten",
        "parameters": {
          "background": "white",
          "metadata_stripped": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a0/4e/a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "release_eligible": false,
      "role": "flattened_white",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:alpha-white"
    },
    "flattened_black": {
      "artifact_id": "artifact:scan-f369b7813391:flattened-black",
      "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-f369b7813391:original",
      "transformation": {
        "transformation_id": "transform:flattened-black",
        "type": "alpha_flatten",
        "parameters": {
          "background": "black",
          "metadata_stripped": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a0/4e/a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "release_eligible": false,
      "role": "flattened_black",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:alpha-black"
    },
    "grayscale": {
      "artifact_id": "artifact:scan-f369b7813391:grayscale",
      "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:grayscale",
        "type": "grayscale",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a0/4e/a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "release_eligible": false,
      "role": "grayscale",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:grayscale"
    },
    "otsu-threshold": {
      "artifact_id": "artifact:scan-f369b7813391:otsu-threshold",
      "sha256": "sha256:078c16bb4dd937df9114b9cde349a34de2f2bd735a23fcdb04e7b2258e9ec966",
      "media_type": "image/png",
      "size_bytes": 2011,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:otsu-threshold",
        "type": "otsu_threshold",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/07/8c/078c16bb4dd937df9114b9cde349a34de2f2bd735a23fcdb04e7b2258e9ec966",
      "release_eligible": false,
      "role": "otsu-threshold",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:otsu-threshold"
    },
    "inverted-grayscale": {
      "artifact_id": "artifact:scan-f369b7813391:inverted-grayscale",
      "sha256": "sha256:e0a2c0ae0e44fa2ff3b2d8644561722aaf8435f6d08673af21bddd7954ab884c",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:inverted-grayscale",
        "type": "inverted_grayscale",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/e0/a2/e0a2c0ae0e44fa2ff3b2d8644561722aaf8435f6d08673af21bddd7954ab884c",
      "release_eligible": false,
      "role": "inverted-grayscale",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:inverted-grayscale"
    },
    "red-channel": {
      "artifact_id": "artifact:scan-f369b7813391:red-channel",
      "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:red-channel",
        "type": "red_channel",
        "parameters": {
          "source_channel": "red"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a0/4e/a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "release_eligible": false,
      "role": "red-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:red-channel"
    },
    "green-channel": {
      "artifact_id": "artifact:scan-f369b7813391:green-channel",
      "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:green-channel",
        "type": "green_channel",
        "parameters": {
          "source_channel": "green"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a0/4e/a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "release_eligible": false,
      "role": "green-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:green-channel"
    },
    "blue-channel": {
      "artifact_id": "artifact:scan-f369b7813391:blue-channel",
      "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "media_type": "image/png",
      "size_bytes": 4617,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:blue-channel",
        "type": "blue_channel",
        "parameters": {
          "source_channel": "blue"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/a0/4e/a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
      "release_eligible": false,
      "role": "blue-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:blue-channel"
    },
    "alpha-channel": {
      "artifact_id": "artifact:scan-f369b7813391:alpha-channel",
      "sha256": "sha256:be333bcb11b3225ad77925ba93a7629c410dfe4261e19d6b15873ac385e71e18",
      "media_type": "image/png",
      "size_bytes": 1016,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:alpha-channel",
        "type": "alpha_channel",
        "parameters": {
          "source_channel": "alpha"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/be/33/be333bcb11b3225ad77925ba93a7629c410dfe4261e19d6b15873ac385e71e18",
      "release_eligible": false,
      "role": "alpha-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:alpha-channel"
    },
    "2x-enlargement": {
      "artifact_id": "artifact:scan-f369b7813391:2x-enlargement",
      "sha256": "sha256:ac839e00437dd760b19105f5912531f0de854fc656236b78d51054438d6ada68",
      "media_type": "image/png",
      "size_bytes": 14862,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:2x-enlargement",
        "type": "2x_enlargement",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/ac/83/ac839e00437dd760b19105f5912531f0de854fc656236b78d51054438d6ada68",
      "release_eligible": false,
      "role": "2x-enlargement",
      "width": 1280,
      "height": 480,
      "frame_index": null,
      "representation_id": "repr:2x-enlargement"
    },
    "white-text-extract": {
      "artifact_id": "artifact:scan-f369b7813391:white-text-extract",
      "sha256": "sha256:950df46ded3e24a76a637e7ededaf2d4c8ba25ec46e2935b9aa5b6516762b342",
      "media_type": "image/png",
      "size_bytes": 1506,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:white-text-extract",
        "type": "white_text_extract",
        "parameters": {
          "method": "invert_threshold",
          "threshold": 60
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/95/0d/950df46ded3e24a76a637e7ededaf2d4c8ba25ec46e2935b9aa5b6516762b342",
      "release_eligible": false,
      "role": "white-text-extract",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:white-text-extract"
    },
    "bg-normalised": {
      "artifact_id": "artifact:scan-f369b7813391:bg-normalised",
      "sha256": "sha256:3d3098d75a0b5ef147fb7e1971969309dc18e8893346b7240a73e2a02d2bb7f3",
      "media_type": "image/png",
      "size_bytes": 5063,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:bg-normalised",
        "type": "bg_normalised",
        "parameters": {
          "method": "background_divide",
          "radius": 25,
          "scale": 175
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/3d/30/3d3098d75a0b5ef147fb7e1971969309dc18e8893346b7240a73e2a02d2bb7f3",
      "release_eligible": false,
      "role": "bg-normalised",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:bg-normalised"
    },
    "sharpen-contrast": {
      "artifact_id": "artifact:scan-f369b7813391:sharpen-contrast",
      "sha256": "sha256:9102db8741ff6c6bbdb43a22897e9c7beb40a141197c5592ef6dfcae871558ca",
      "media_type": "image/png",
      "size_bytes": 6556,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-f369b7813391:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:sharpen-contrast",
        "type": "sharpen_contrast",
        "parameters": {
          "sharpness": 2.0,
          "contrast": 3.0
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/91/02/9102db8741ff6c6bbdb43a22897e9c7beb40a141197c5592ef6dfcae871558ca",
      "release_eligible": false,
      "role": "sharpen-contrast",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:sharpen-contrast"
    }
  },
  "representation_manifest": {
    "entries": [
      {
        "representation_id": "repr:2x-enlargement",
        "artifact_id": "artifact:scan-f369b7813391:2x-enlargement",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:ac839e00437dd760b19105f5912531f0de854fc656236b78d51054438d6ada68",
        "width": 1280,
        "height": 480,
        "frame_index": null,
        "transformation_id": "transform:2x-enlargement",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-channel",
        "artifact_id": "artifact:scan-f369b7813391:alpha-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:be333bcb11b3225ad77925ba93a7629c410dfe4261e19d6b15873ac385e71e18",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:alpha-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:bg-normalised",
        "artifact_id": "artifact:scan-f369b7813391:bg-normalised",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:3d3098d75a0b5ef147fb7e1971969309dc18e8893346b7240a73e2a02d2bb7f3",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:bg-normalised",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:blue-channel",
        "artifact_id": "artifact:scan-f369b7813391:blue-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:blue-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:canonical-lossless",
        "artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "kind": "canonical_lossless",
        "source_artifact_id": "artifact:scan-f369b7813391:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:canonical-lossless",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:release-candidate",
        "artifact_id": "artifact:scan-f369b7813391:canonical-lossy",
        "kind": "release_candidate",
        "source_artifact_id": "artifact:scan-f369b7813391:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/jpeg",
        "sha256": "sha256:a9cb5d2ef47babdda154e042d9efa026b98d284c417a687cf365dc1025497923",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:canonical-lossy",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-black",
        "artifact_id": "artifact:scan-f369b7813391:flattened-black",
        "kind": "alpha_view",
        "source_artifact_id": "artifact:scan-f369b7813391:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:flattened-black",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-white",
        "artifact_id": "artifact:scan-f369b7813391:flattened-white",
        "kind": "alpha_view",
        "source_artifact_id": "artifact:scan-f369b7813391:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:flattened-white",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:grayscale",
        "artifact_id": "artifact:scan-f369b7813391:grayscale",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:grayscale",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:green-channel",
        "artifact_id": "artifact:scan-f369b7813391:green-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:green-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:inverted-grayscale",
        "artifact_id": "artifact:scan-f369b7813391:inverted-grayscale",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:e0a2c0ae0e44fa2ff3b2d8644561722aaf8435f6d08673af21bddd7954ab884c",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:inverted-grayscale",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:original",
        "artifact_id": "artifact:scan-f369b7813391:original",
        "kind": "original_container",
        "source_artifact_id": "artifact:scan-f369b7813391:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:02e70d635554f7102c5f1cc9c011dfaf077dbd3037c1ef38e9d2fff944aa6ed1",
        "width": null,
        "height": null,
        "frame_index": null,
        "transformation_id": null,
        "coverage_notes": []
      },
      {
        "representation_id": "repr:otsu-threshold",
        "artifact_id": "artifact:scan-f369b7813391:otsu-threshold",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:078c16bb4dd937df9114b9cde349a34de2f2bd735a23fcdb04e7b2258e9ec966",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:otsu-threshold",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:red-channel",
        "artifact_id": "artifact:scan-f369b7813391:red-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:a04eb5a3cec67be335731cec971beb1e2b04a7275fc78ad99a795b3ae89293c0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:red-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:sharpen-contrast",
        "artifact_id": "artifact:scan-f369b7813391:sharpen-contrast",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:9102db8741ff6c6bbdb43a22897e9c7beb40a141197c5592ef6dfcae871558ca",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:sharpen-contrast",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:white-text-extract",
        "artifact_id": "artifact:scan-f369b7813391:white-text-extract",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:950df46ded3e24a76a637e7ededaf2d4c8ba25ec46e2935b9aa5b6516762b342",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:white-text-extract",
        "coverage_notes": []
      }
    ],
    "coverage_complete": true,
    "missing_required": []
  },
  "observations": [
    {
      "observation_id": "observation:scan-f369b7813391:ocr:000",
      "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossy",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:canonical-lossy",
      "location": {
        "artifact_label": "release_candidate"
      },
      "sha256": "sha256:135f8cc103c1e0dee10f17e898e523e7fd7f8dabb60c41f974322c6f8bfb13a7",
      "length": 63
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:001",
      "source_artifact_id": "artifact:scan-f369b7813391:canonical-lossless",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:canonical-lossless",
      "location": {
        "artifact_label": "canonical_lossless"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:002",
      "source_artifact_id": "artifact:scan-f369b7813391:flattened-white",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:flattened-white",
      "location": {
        "artifact_label": "flattened_white"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:003",
      "source_artifact_id": "artifact:scan-f369b7813391:flattened-black",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:flattened-black",
      "location": {
        "artifact_label": "flattened_black"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:004",
      "source_artifact_id": "artifact:scan-f369b7813391:grayscale",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:grayscale",
      "location": {
        "artifact_label": "grayscale"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:005",
      "source_artifact_id": "artifact:scan-f369b7813391:otsu-threshold",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:otsu-threshold",
      "location": {
        "artifact_label": "otsu-threshold"
      },
      "sha256": "sha256:ff92b62d46a6bff68172b6d9da51f79dcec19a23c37e47154d16102d5352b301",
      "length": 63
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:006",
      "source_artifact_id": "artifact:scan-f369b7813391:inverted-grayscale",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:inverted-grayscale",
      "location": {
        "artifact_label": "inverted-grayscale"
      },
      "sha256": "sha256:135f8cc103c1e0dee10f17e898e523e7fd7f8dabb60c41f974322c6f8bfb13a7",
      "length": 63
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:007",
      "source_artifact_id": "artifact:scan-f369b7813391:red-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:red-channel",
      "location": {
        "artifact_label": "red-channel"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:008",
      "source_artifact_id": "artifact:scan-f369b7813391:green-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:green-channel",
      "location": {
        "artifact_label": "green-channel"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:009",
      "source_artifact_id": "artifact:scan-f369b7813391:blue-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:blue-channel",
      "location": {
        "artifact_label": "blue-channel"
      },
      "sha256": "sha256:1058a284e21488d6f43bea9c31bb3eb5c3f3310dc978bacd495e1179acc382df",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:010",
      "source_artifact_id": "artifact:scan-f369b7813391:2x-enlargement",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:2x-enlargement",
      "location": {
        "artifact_label": "2x-enlargement"
      },
      "sha256": "sha256:22201c9e64e44a96e8e1adb31b8d36977fb311569856cc007059c2602a5b4e7e",
      "length": 64
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:011",
      "source_artifact_id": "artifact:scan-f369b7813391:white-text-extract",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:white-text-extract",
      "location": {
        "artifact_label": "white-text-extract"
      },
      "sha256": "sha256:5985c29e295768df7c4bfbe39a7217f583a6070c43b5a30f4c25c1b209ef4360",
      "length": 62
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:012",
      "source_artifact_id": "artifact:scan-f369b7813391:bg-normalised",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:bg-normalised",
      "location": {
        "artifact_label": "bg-normalised"
      },
      "sha256": "sha256:1d18c33d961d32e88305bbd4e2da6937d4847f96a876a30e5d03d7bfc54609aa",
      "length": 64
    },
    {
      "observation_id": "observation:scan-f369b7813391:ocr:013",
      "source_artifact_id": "artifact:scan-f369b7813391:sharpen-contrast",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:sharpen-contrast",
      "location": {
        "artifact_label": "sharpen-contrast"
      },
      "sha256": "sha256:538e2ad4343a8c4be35b0f41165cd51959421d999e91039ead692de15c79d2f0",
      "length": 62
    }
  ],
  "detector_executions": [
    {
      "detector_id": "detector:metadata-builtin",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "metadata",
      "category": "privacy",
      "required": true,
      "started_at": "2026-06-29T12:34:26.547836Z",
      "completed_at": "2026-06-29T12:34:26.548169Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:exiftool",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "metadata",
      "category": "privacy",
      "required": false,
      "started_at": "2026-06-29T12:34:26.548194Z",
      "completed_at": "2026-06-29T12:34:26.640080Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": "13.55"
    },
    {
      "detector_id": "detector:malware-clamav",
      "status": "ERROR",
      "state": "ERROR",
      "family": "malware",
      "category": "malware",
      "required": false,
      "started_at": "2026-06-29T12:34:26.640302Z",
      "completed_at": "2026-06-29T12:34:26.669976Z",
      "duration_ms": 17.212958002346568,
      "reason": "signature_database_missing",
      "tool_version": "ClamAV 1.5.2"
    },
    {
      "detector_id": "detector:malware-yara",
      "status": "ERROR",
      "state": "ERROR",
      "family": "malware",
      "category": "malware",
      "required": false,
      "started_at": "2026-06-29T12:34:26.670088Z",
      "completed_at": "2026-06-29T12:34:26.670139Z",
      "duration_ms": null,
      "reason": "yara_rule_bundle_missing",
      "tool_version": null
    },
    {
      "detector_id": "detector:embedded-binwalk",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "embedded_payload",
      "category": "embedded_payload",
      "required": false,
      "started_at": "2026-06-29T12:34:26.670154Z",
      "completed_at": "2026-06-29T12:34:26.690771Z",
      "duration_ms": 9.854125004494563,
      "reason": null,
      "tool_version": "Analyzes data for embedded file types"
    },
    {
      "detector_id": "detector:tesseract",
      "status": "SUCCESS",
      "state": "CONFIRMED",
      "family": "OCR",
      "category": "prompt_injection",
      "required": false,
      "started_at": "2026-06-29T12:34:26.691243Z",
      "completed_at": "2026-06-29T12:34:27.668467Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": "tesseract 5.5.2"
    },
    {
      "detector_id": "detector:qr-pyzbar",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "QR/barcode",
      "category": "embedded_payload",
      "required": false,
      "started_at": "2026-06-29T12:34:29.472258Z",
      "completed_at": "2026-06-29T12:34:29.472258Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:prompt-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "prompt",
      "category": "prompt_injection",
      "required": true,
      "started_at": "2026-06-29T12:34:29.472810Z",
      "completed_at": "2026-06-29T12:34:29.474752Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:semantic-scorer",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "prompt",
      "category": "prompt_injection",
      "required": false,
      "started_at": "2026-06-29T12:34:29.474758Z",
      "completed_at": "2026-06-29T12:34:29.475020Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:privacy-rules",
      "status": "SUCCESS",
      "state": "CONFIRMED",
      "family": "privacy",
      "category": "privacy",
      "required": false,
      "started_at": "2026-06-29T12:34:29.475024Z",
      "completed_at": "2026-06-29T12:34:29.475094Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:phishing-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "phishing",
      "category": "phishing",
      "required": false,
      "started_at": "2026-06-29T12:34:29.475097Z",
      "completed_at": "2026-06-29T12:34:29.475119Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:visible-watermark-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "watermarks",
      "category": "watermarks",
      "required": false,
      "started_at": "2026-06-29T12:34:29.475127Z",
      "completed_at": "2026-06-29T12:34:29.475127Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    }
  ],
  "release_grants": [],
  "coverage": {
    "original_container": "high",
    "all_frames": "complete",
    "visible_text": "medium",
    "low_contrast_text": "medium",
    "metadata_text": "medium",
    "known_embedded_formats": "low",
    "common_steganography": "low",
    "unknown_steganography": "low",
    "registered_watermark_schemes": "low",
    "unknown_watermarks": "unsupported",
    "model_specific_adversarial_attacks": "not_tested",
    "universal_attack_absence": "impossible",
    "universal_absence_claim": false
  },
  "module_status": {
    "artifact_store": {
      "name": "artifact_store",
      "status": "CONFIRMED",
      "reason": "/Users/lohith-uncovai/argus-eval-data/corpus/prompt_injection/data/argus.sqlite3",
      "version": null
    },
    "opencv_decoder": {
      "name": "opencv_decoder",
      "status": "CONFIRMED",
      "reason": null,
      "version": null
    },
    "release_candidate_decoder": {
      "name": "opencv_decoder",
      "status": "CONFIRMED",
      "reason": null,
      "version": null
    },
    "metadata_builtin": {
      "name": "metadata_builtin",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": null
    },
    "exiftool": {
      "name": "exiftool",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": "13.55"
    },
    "binwalk": {
      "name": "binwalk",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": "Analyzes data for embedded file types"
    },
    "clamav": {
      "name": "clamav",
      "status": "ERROR",
      "reason": "signature_database_missing",
      "version": "ClamAV 1.5.2"
    },
    "yara": {
      "name": "yara",
      "status": "ERROR",
      "reason": "yara_rule_bundle_missing",
      "version": null
    },
    "c2pa": {
      "name": "c2pa",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "paddleocr": {
      "name": "paddleocr",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "zsteg": {
      "name": "zsteg",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "embedded_thumbnails": {
      "name": "embedded_thumbnails",
      "status": "NO_EVIDENCE_FOUND",
      "reason": "no embedded thumbnails found",
      "version": null
    },
    "watermark_registry": {
      "name": "watermark_registry",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "redaction_analysis": {
      "name": "redaction_analysis",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "adversarial_stability": {
      "name": "adversarial_stability",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "visual_analyzer": {
      "name": "visual_analyzer",
      "status": "NOT_TESTED",
      "reason": "NullVisualAnalyzer configured",
      "version": null
    },
    "tesseract": {
      "name": "tesseract",
      "status": "CONFIRMED",
      "reason": null,
      "version": "tesseract 5.5.2"
    },
    "qr": {
      "name": "qr",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": null
    },
    "steganalysis_statistics": {
      "name": "steganalysis_statistics",
      "status": "CONFIRMED",
      "reason": "{'grayscale_entropy': 0.21686660154012993}",
      "version": null
    }
  },
  "limitations": [
    {
      "limitation_id": "limitation:universal-safety",
      "category": "global",
      "description": "No report can prove an image is universally safe."
    },
    {
      "limitation_id": "limitation:unknown-steganography",
      "category": "steganography",
      "description": "Arbitrary encrypted steganography cannot be excluded."
    },
    {
      "limitation_id": "limitation:unknown-watermarks",
      "category": "watermarks",
      "description": "Unknown watermark schemes are not exhaustively detectable."
    }
  ],
  "errors": [],
  "timings_ms": {
    "total_ms": 3186.3237919969833
  },
  "evidence_graph": {
    "nodes": [
      {
        "id": "artifact:scan-f369b7813391:original",
        "type": "Artifact",
        "role": "original"
      },
      {
        "id": "artifact:scan-f369b7813391:canonical-lossy",
        "type": "Artifact",
        "role": "canonical_lossy"
      },
      {
        "id": "artifact:scan-f369b7813391:canonical-lossless",
        "type": "Artifact",
        "role": "canonical_lossless"
      },
      {
        "id": "artifact:scan-f369b7813391:flattened-white",
        "type": "Artifact",
        "role": "flattened_white"
      },
      {
        "id": "artifact:scan-f369b7813391:flattened-black",
        "type": "Artifact",
        "role": "flattened_black"
      },
      {
        "id": "artifact:scan-f369b7813391:grayscale",
        "type": "Artifact",
        "role": "grayscale"
      },
      {
        "id": "artifact:scan-f369b7813391:otsu-threshold",
        "type": "Artifact",
        "role": "otsu-threshold"
      },
      {
        "id": "artifact:scan-f369b7813391:inverted-grayscale",
        "type": "Artifact",
        "role": "inverted-grayscale"
      },
      {
        "id": "artifact:scan-f369b7813391:red-channel",
        "type": "Artifact",
        "role": "red-channel"
      },
      {
        "id": "artifact:scan-f369b7813391:green-channel",
        "type": "Artifact",
        "role": "green-channel"
      },
      {
        "id": "artifact:scan-f369b7813391:blue-channel",
        "type": "Artifact",
        "role": "blue-channel"
      },
      {
        "id": "artifact:scan-f369b7813391:alpha-channel",
        "type": "Artifact",
        "role": "alpha-channel"
      },
      {
        "id": "artifact:scan-f369b7813391:2x-enlargement",
        "type": "Artifact",
        "role": "2x-enlargement"
      },
      {
        "id": "artifact:scan-f369b7813391:white-text-extract",
        "type": "Artifact",
        "role": "white-text-extract"
      },
      {
        "id": "artifact:scan-f369b7813391:bg-normalised",
        "type": "Artifact",
        "role": "bg-normalised"
      },
      {
        "id": "artifact:scan-f369b7813391:sharpen-contrast",
        "type": "Artifact",
        "role": "sharpen-contrast"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:000",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:001",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:002",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:003",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:004",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:005",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:006",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:007",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:008",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:009",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:010",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:011",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:012",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-f369b7813391:ocr:013",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "finding:scan-f369b7813391:privacy:000",
        "type": "Finding",
        "category": "privacy"
      }
    ],
    "edges": [
      {
        "from": "artifact:scan-f369b7813391:original",
        "to": "artifact:scan-f369b7813391:canonical-lossy",
        "type": "derived_from",
        "transformation": "transform:canonical-lossy"
      },
      {
        "from": "artifact:scan-f369b7813391:original",
        "to": "artifact:scan-f369b7813391:canonical-lossless",
        "type": "derived_from",
        "transformation": "transform:canonical-lossless"
      },
      {
        "from": "artifact:scan-f369b7813391:original",
        "to": "artifact:scan-f369b7813391:flattened-white",
        "type": "derived_from",
        "transformation": "transform:flattened-white"
      },
      {
        "from": "artifact:scan-f369b7813391:original",
        "to": "artifact:scan-f369b7813391:flattened-black",
        "type": "derived_from",
        "transformation": "transform:flattened-black"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:grayscale",
        "type": "derived_from",
        "transformation": "transform:grayscale"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:otsu-threshold",
        "type": "derived_from",
        "transformation": "transform:otsu-threshold"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:inverted-grayscale",
        "type": "derived_from",
        "transformation": "transform:inverted-grayscale"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:red-channel",
        "type": "derived_from",
        "transformation": "transform:red-channel"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:green-channel",
        "type": "derived_from",
        "transformation": "transform:green-channel"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:blue-channel",
        "type": "derived_from",
        "transformation": "transform:blue-channel"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:alpha-channel",
        "type": "derived_from",
        "transformation": "transform:alpha-channel"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:2x-enlargement",
        "type": "derived_from",
        "transformation": "transform:2x-enlargement"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:white-text-extract",
        "type": "derived_from",
        "transformation": "transform:white-text-extract"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:bg-normalised",
        "type": "derived_from",
        "transformation": "transform:bg-normalised"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "artifact:scan-f369b7813391:sharpen-contrast",
        "type": "derived_from",
        "transformation": "transform:sharpen-contrast"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossy",
        "to": "observation:scan-f369b7813391:ocr:000",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:canonical-lossless",
        "to": "observation:scan-f369b7813391:ocr:001",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:flattened-white",
        "to": "observation:scan-f369b7813391:ocr:002",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:flattened-black",
        "to": "observation:scan-f369b7813391:ocr:003",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:grayscale",
        "to": "observation:scan-f369b7813391:ocr:004",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:otsu-threshold",
        "to": "observation:scan-f369b7813391:ocr:005",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:inverted-grayscale",
        "to": "observation:scan-f369b7813391:ocr:006",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:red-channel",
        "to": "observation:scan-f369b7813391:ocr:007",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:green-channel",
        "to": "observation:scan-f369b7813391:ocr:008",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:blue-channel",
        "to": "observation:scan-f369b7813391:ocr:009",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:2x-enlargement",
        "to": "observation:scan-f369b7813391:ocr:010",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:white-text-extract",
        "to": "observation:scan-f369b7813391:ocr:011",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:bg-normalised",
        "to": "observation:scan-f369b7813391:ocr:012",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-f369b7813391:sharpen-contrast",
        "to": "observation:scan-f369b7813391:ocr:013",
        "type": "observed_in"
      },
      {
        "from": "observation:scan-f369b7813391:ocr:013",
        "to": "finding:scan-f369b7813391:privacy:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-f369b7813391:sharpen-contrast",
        "to": "finding:scan-f369b7813391:privacy:000",
        "type": "supports"
      }
    ]
  }
}
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 


(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % argus-img scan ~/argus-eval-data/corpus/prompt_injection/prompt-plain-visible-000.png --mode deep --profile HUMAN_VIEW

{
  "schema_version": "1.0.0",
  "scan_id": "scan-ed05d3f1b430",
  "created_at": "2026-06-29T12:35:47.109480Z",
  "scanner": {
    "name": "argus-img",
    "version": "0.1.0",
    "offline_mode": true,
    "mode": "deep",
    "use_profile": "HUMAN_VIEW",
    "configuration_hash": "sha256:ec6c5cde5fd9244ebd02fe4994179e6d164b80e89b1a87948faee2f5564934a0"
  },
  "input": {
    "original_filename": "prompt-plain-visible-000.png",
    "size_bytes": 8122,
    "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
    "declared_mime": null,
    "detected_mime": "image/png",
    "format": "PNG",
    "width": 640,
    "height": 240,
    "frames": 1,
    "quarantined_artifact_id": "artifact:scan-ed05d3f1b430:original"
  },
  "decision": {
    "action": "REVIEW",
    "safe_claim": false,
    "reason_codes": [
      "INSTRUCTION_OVERRIDE",
      "PROMPT_INJECTION"
    ],
    "triggered_policy_rules": [
      "human-review-prompt"
    ],
    "winning_rule_id": "human-review-prompt",
    "winning_rule_priority": 700,
    "summary": "",
    "explanation": "Rule human-review-prompt matched finding finding:scan-ed05d3f1b430:prompt:000."
  },
  "assessments": {
    "file_security": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "malware": {
      "state": "ERROR",
      "likelihood": null,
      "impact": "low",
      "coverage": "partial",
      "finding_ids": [],
      "limitations": [
        "detector:malware-clamav: ERROR",
        "detector:malware-yara: ERROR"
      ],
      "summary": "Assessment limited by detector coverage: ERROR."
    },
    "embedded_payload": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "prompt_injection": {
      "state": "CONFIRMED",
      "likelihood": 0.95,
      "impact": "critical",
      "coverage": "medium",
      "finding_ids": [
        "finding:scan-ed05d3f1b430:prompt:000"
      ],
      "limitations": [],
      "summary": "1 finding(s)"
    },
    "covert_channel": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Arbitrary encrypted steganography cannot be excluded."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "steganography": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Arbitrary encrypted steganography cannot be excluded."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "watermarks": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "low",
      "finding_ids": [],
      "limitations": [
        "Unknown watermark schemes are unsupported."
      ],
      "summary": "No evidence found in executed checks."
    },
    "provenance": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "phishing": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "privacy": {
      "state": "NO_EVIDENCE_FOUND",
      "likelihood": null,
      "impact": "low",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [],
      "summary": "No evidence found in executed checks."
    },
    "redaction_failure": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "adversarial_instability": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category.",
        "Model-specific adversarial perturbations were not fully tested."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    },
    "authenticity_indicators": {
      "state": "NOT_TESTED",
      "likelihood": null,
      "impact": "low",
      "coverage": "not_tested",
      "finding_ids": [],
      "limitations": [
        "No detector execution was recorded for this category."
      ],
      "summary": "Assessment limited by detector coverage: NOT_TESTED."
    }
  },
  "findings": [
    {
      "finding_id": "finding:scan-ed05d3f1b430:prompt:000",
      "category": "prompt_injection",
      "type": "instruction_override",
      "state": "CONFIRMED",
      "severity": "critical",
      "detector_confidence": null,
      "evidence_quality": 0.85,
      "attack_likelihood": 0.95,
      "impact": "critical",
      "source_artifact_ids": [
        "artifact:scan-ed05d3f1b430:2x-enlargement",
        "artifact:scan-ed05d3f1b430:bg-normalised",
        "artifact:scan-ed05d3f1b430:blue-channel",
        "artifact:scan-ed05d3f1b430:canonical-lossless",
        "artifact:scan-ed05d3f1b430:canonical-lossy",
        "artifact:scan-ed05d3f1b430:flattened-black",
        "artifact:scan-ed05d3f1b430:flattened-white",
        "artifact:scan-ed05d3f1b430:grayscale",
        "artifact:scan-ed05d3f1b430:green-channel",
        "artifact:scan-ed05d3f1b430:inverted-grayscale",
        "artifact:scan-ed05d3f1b430:otsu-threshold",
        "artifact:scan-ed05d3f1b430:red-channel",
        "artifact:scan-ed05d3f1b430:sharpen-contrast",
        "artifact:scan-ed05d3f1b430:white-text-extract"
      ],
      "observation_ids": [
        "observation:scan-ed05d3f1b430:ocr:000",
        "observation:scan-ed05d3f1b430:ocr:001",
        "observation:scan-ed05d3f1b430:ocr:002",
        "observation:scan-ed05d3f1b430:ocr:003",
        "observation:scan-ed05d3f1b430:ocr:004",
        "observation:scan-ed05d3f1b430:ocr:005",
        "observation:scan-ed05d3f1b430:ocr:006",
        "observation:scan-ed05d3f1b430:ocr:007",
        "observation:scan-ed05d3f1b430:ocr:008",
        "observation:scan-ed05d3f1b430:ocr:009",
        "observation:scan-ed05d3f1b430:ocr:010",
        "observation:scan-ed05d3f1b430:ocr:011",
        "observation:scan-ed05d3f1b430:ocr:012",
        "observation:scan-ed05d3f1b430:ocr:013"
      ],
      "detector_ids": [
        "detector:prompt-rules"
      ],
      "reason_codes": [
        "INSTRUCTION_OVERRIDE",
        "PROMPT_INJECTION"
      ],
      "recommended_action": "BLOCK",
      "limitations": [
        "Context classification is deterministic and may misclassify quoted text."
      ],
      "evidence": {
        "text_sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
        "text_length": 58,
        "full_text_returned": false,
        "forensic_evidence_required": true,
        "matched_rule_ids": [
          "PI-INSTRUCTION-OVERRIDE-EN-001"
        ],
        "intent": {
          "speaker_claim": null,
          "requested_action": null,
          "target": null,
          "authority_override": true,
          "secrecy_requested": false,
          "data_exfiltration": false,
          "credential_request": false,
          "quoted_or_active": "active"
        }
      }
    }
  ],
  "artifacts": {
    "original": {
      "artifact_id": "artifact:scan-ed05d3f1b430:original",
      "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "media_type": "image/png",
      "size_bytes": 8122,
      "created_by": "intake",
      "derived_from": null,
      "transformation": null,
      "storage_reference": "quarantine/1f/cd/1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "release_eligible": false,
      "role": "original",
      "width": null,
      "height": null,
      "frame_index": null,
      "representation_id": "repr:original"
    },
    "canonical_lossy": {
      "artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossy",
      "sha256": "sha256:13c1a666a2e24fed7aad91394225e63387d6dc2ccaa54e6ba463956c34800305",
      "media_type": "image/jpeg",
      "size_bytes": 12333,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-ed05d3f1b430:original",
      "transformation": {
        "transformation_id": "transform:canonical-lossy",
        "type": "canonical_lossy_jpeg",
        "parameters": {
          "metadata_stripped": true,
          "lossy": true,
          "flattened": true,
          "alpha_composited": true,
          "background": "white",
          "quality": 90
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/13/c1/13c1a666a2e24fed7aad91394225e63387d6dc2ccaa54e6ba463956c34800305",
      "release_eligible": false,
      "role": "canonical_lossy",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:release-candidate"
    },
    "canonical_lossless": {
      "artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "media_type": "image/png",
      "size_bytes": 8122,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-ed05d3f1b430:original",
      "transformation": {
        "transformation_id": "transform:canonical-lossless",
        "type": "canonical_lossless_png",
        "parameters": {
          "metadata_stripped": true,
          "orientation_applied": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/1f/cd/1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "release_eligible": false,
      "role": "canonical_lossless",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:canonical-lossless"
    },
    "flattened_white": {
      "artifact_id": "artifact:scan-ed05d3f1b430:flattened-white",
      "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "media_type": "image/png",
      "size_bytes": 8122,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-ed05d3f1b430:original",
      "transformation": {
        "transformation_id": "transform:flattened-white",
        "type": "alpha_flatten",
        "parameters": {
          "background": "white",
          "metadata_stripped": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/1f/cd/1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "release_eligible": false,
      "role": "flattened_white",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:alpha-white"
    },
    "flattened_black": {
      "artifact_id": "artifact:scan-ed05d3f1b430:flattened-black",
      "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "media_type": "image/png",
      "size_bytes": 8122,
      "created_by": "canonical-reconstruction",
      "derived_from": "artifact:scan-ed05d3f1b430:original",
      "transformation": {
        "transformation_id": "transform:flattened-black",
        "type": "alpha_flatten",
        "parameters": {
          "background": "black",
          "metadata_stripped": true
        },
        "inverse_coordinate_mapping": null,
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/1f/cd/1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
      "release_eligible": false,
      "role": "flattened_black",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:alpha-black"
    },
    "grayscale": {
      "artifact_id": "artifact:scan-ed05d3f1b430:grayscale",
      "sha256": "sha256:11570bc62186f19f95a82031af443e69741b60c78389a1f220e7255c7f19eb37",
      "media_type": "image/png",
      "size_bytes": 7662,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:grayscale",
        "type": "grayscale",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/11/57/11570bc62186f19f95a82031af443e69741b60c78389a1f220e7255c7f19eb37",
      "release_eligible": false,
      "role": "grayscale",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:grayscale"
    },
    "otsu-threshold": {
      "artifact_id": "artifact:scan-ed05d3f1b430:otsu-threshold",
      "sha256": "sha256:7fefd94afa741f129389ee52fd3a504fedc593d8b593d263ed4ace89fe7ddbe9",
      "media_type": "image/png",
      "size_bytes": 2238,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:otsu-threshold",
        "type": "otsu_threshold",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/7f/ef/7fefd94afa741f129389ee52fd3a504fedc593d8b593d263ed4ace89fe7ddbe9",
      "release_eligible": false,
      "role": "otsu-threshold",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:otsu-threshold"
    },
    "inverted-grayscale": {
      "artifact_id": "artifact:scan-ed05d3f1b430:inverted-grayscale",
      "sha256": "sha256:4a6a58cde9195bd9bc2aef995ae0aa4cfa1fd2dcb0ca9b4601d8c8e829e31443",
      "media_type": "image/png",
      "size_bytes": 7655,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:inverted-grayscale",
        "type": "inverted_grayscale",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/4a/6a/4a6a58cde9195bd9bc2aef995ae0aa4cfa1fd2dcb0ca9b4601d8c8e829e31443",
      "release_eligible": false,
      "role": "inverted-grayscale",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:inverted-grayscale"
    },
    "red-channel": {
      "artifact_id": "artifact:scan-ed05d3f1b430:red-channel",
      "sha256": "sha256:b4e44611ae474450e002e5eab1f9808771851edbf58999ec1ab4f7a2aeafd54c",
      "media_type": "image/png",
      "size_bytes": 7601,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:red-channel",
        "type": "red_channel",
        "parameters": {
          "source_channel": "red"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/b4/e4/b4e44611ae474450e002e5eab1f9808771851edbf58999ec1ab4f7a2aeafd54c",
      "release_eligible": false,
      "role": "red-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:red-channel"
    },
    "green-channel": {
      "artifact_id": "artifact:scan-ed05d3f1b430:green-channel",
      "sha256": "sha256:b4e44611ae474450e002e5eab1f9808771851edbf58999ec1ab4f7a2aeafd54c",
      "media_type": "image/png",
      "size_bytes": 7601,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:green-channel",
        "type": "green_channel",
        "parameters": {
          "source_channel": "green"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/b4/e4/b4e44611ae474450e002e5eab1f9808771851edbf58999ec1ab4f7a2aeafd54c",
      "release_eligible": false,
      "role": "green-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:green-channel"
    },
    "blue-channel": {
      "artifact_id": "artifact:scan-ed05d3f1b430:blue-channel",
      "sha256": "sha256:4ed1006215f1d0ef726762ab0bf29279c2e041891ddfc03e69a917c71d8374a1",
      "media_type": "image/png",
      "size_bytes": 7902,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:blue-channel",
        "type": "blue_channel",
        "parameters": {
          "source_channel": "blue"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/4e/d1/4ed1006215f1d0ef726762ab0bf29279c2e041891ddfc03e69a917c71d8374a1",
      "release_eligible": false,
      "role": "blue-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:blue-channel"
    },
    "alpha-channel": {
      "artifact_id": "artifact:scan-ed05d3f1b430:alpha-channel",
      "sha256": "sha256:be333bcb11b3225ad77925ba93a7629c410dfe4261e19d6b15873ac385e71e18",
      "media_type": "image/png",
      "size_bytes": 1016,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:alpha-channel",
        "type": "alpha_channel",
        "parameters": {
          "source_channel": "alpha"
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/be/33/be333bcb11b3225ad77925ba93a7629c410dfe4261e19d6b15873ac385e71e18",
      "release_eligible": false,
      "role": "alpha-channel",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:alpha-channel"
    },
    "2x-enlargement": {
      "artifact_id": "artifact:scan-ed05d3f1b430:2x-enlargement",
      "sha256": "sha256:5d7fe159385c8a4de4b48b9e999c5a49675a88df45be47ac144f901a177a3ba5",
      "media_type": "image/png",
      "size_bytes": 37445,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:2x-enlargement",
        "type": "2x_enlargement",
        "parameters": {},
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/5d/7f/5d7fe159385c8a4de4b48b9e999c5a49675a88df45be47ac144f901a177a3ba5",
      "release_eligible": false,
      "role": "2x-enlargement",
      "width": 1280,
      "height": 480,
      "frame_index": null,
      "representation_id": "repr:2x-enlargement"
    },
    "white-text-extract": {
      "artifact_id": "artifact:scan-ed05d3f1b430:white-text-extract",
      "sha256": "sha256:662d79118a5025b0e22f8e8d3129508dee84e56d868008b2eebbbc9c6bc8beb7",
      "media_type": "image/png",
      "size_bytes": 1813,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:white-text-extract",
        "type": "white_text_extract",
        "parameters": {
          "method": "invert_threshold",
          "threshold": 60
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/66/2d/662d79118a5025b0e22f8e8d3129508dee84e56d868008b2eebbbc9c6bc8beb7",
      "release_eligible": false,
      "role": "white-text-extract",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:white-text-extract"
    },
    "bg-normalised": {
      "artifact_id": "artifact:scan-ed05d3f1b430:bg-normalised",
      "sha256": "sha256:5e0c2482227600b86a7eda243aea6cbebf5476451213d605902ef3293ace9ca4",
      "media_type": "image/png",
      "size_bytes": 11388,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:bg-normalised",
        "type": "bg_normalised",
        "parameters": {
          "method": "background_divide",
          "radius": 25,
          "scale": 175
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/5e/0c/5e0c2482227600b86a7eda243aea6cbebf5476451213d605902ef3293ace9ca4",
      "release_eligible": false,
      "role": "bg-normalised",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:bg-normalised"
    },
    "sharpen-contrast": {
      "artifact_id": "artifact:scan-ed05d3f1b430:sharpen-contrast",
      "sha256": "sha256:1818a100f04ce85382286e991a616507eb2701dcf41a084da58b77e8fc88c8bd",
      "media_type": "image/png",
      "size_bytes": 3577,
      "created_by": "transformation-bank",
      "derived_from": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "transformation": {
        "transformation_id": "transform:sharpen-contrast",
        "type": "sharpen_contrast",
        "parameters": {
          "sharpness": 2.0,
          "contrast": 3.0
        },
        "inverse_coordinate_mapping": "identity",
        "reliability_class": "forensic",
        "resource_cost_class": "low"
      },
      "storage_reference": "artifacts/sha256/18/18/1818a100f04ce85382286e991a616507eb2701dcf41a084da58b77e8fc88c8bd",
      "release_eligible": false,
      "role": "sharpen-contrast",
      "width": 640,
      "height": 240,
      "frame_index": null,
      "representation_id": "repr:sharpen-contrast"
    }
  },
  "representation_manifest": {
    "entries": [
      {
        "representation_id": "repr:2x-enlargement",
        "artifact_id": "artifact:scan-ed05d3f1b430:2x-enlargement",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:5d7fe159385c8a4de4b48b9e999c5a49675a88df45be47ac144f901a177a3ba5",
        "width": 1280,
        "height": 480,
        "frame_index": null,
        "transformation_id": "transform:2x-enlargement",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-channel",
        "artifact_id": "artifact:scan-ed05d3f1b430:alpha-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:be333bcb11b3225ad77925ba93a7629c410dfe4261e19d6b15873ac385e71e18",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:alpha-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:bg-normalised",
        "artifact_id": "artifact:scan-ed05d3f1b430:bg-normalised",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:5e0c2482227600b86a7eda243aea6cbebf5476451213d605902ef3293ace9ca4",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:bg-normalised",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:blue-channel",
        "artifact_id": "artifact:scan-ed05d3f1b430:blue-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:4ed1006215f1d0ef726762ab0bf29279c2e041891ddfc03e69a917c71d8374a1",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:blue-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:canonical-lossless",
        "artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "kind": "canonical_lossless",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:canonical-lossless",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:release-candidate",
        "artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossy",
        "kind": "release_candidate",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/jpeg",
        "sha256": "sha256:13c1a666a2e24fed7aad91394225e63387d6dc2ccaa54e6ba463956c34800305",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:canonical-lossy",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-black",
        "artifact_id": "artifact:scan-ed05d3f1b430:flattened-black",
        "kind": "alpha_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:flattened-black",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:alpha-white",
        "artifact_id": "artifact:scan-ed05d3f1b430:flattened-white",
        "kind": "alpha_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:flattened-white",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:grayscale",
        "artifact_id": "artifact:scan-ed05d3f1b430:grayscale",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:11570bc62186f19f95a82031af443e69741b60c78389a1f220e7255c7f19eb37",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:grayscale",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:green-channel",
        "artifact_id": "artifact:scan-ed05d3f1b430:green-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:b4e44611ae474450e002e5eab1f9808771851edbf58999ec1ab4f7a2aeafd54c",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:green-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:inverted-grayscale",
        "artifact_id": "artifact:scan-ed05d3f1b430:inverted-grayscale",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:4a6a58cde9195bd9bc2aef995ae0aa4cfa1fd2dcb0ca9b4601d8c8e829e31443",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:inverted-grayscale",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:original",
        "artifact_id": "artifact:scan-ed05d3f1b430:original",
        "kind": "original_container",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:original",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:1fcd8ac4ed3a509dff1eb79525765cffc78e8d7b7c05f8cab589a2c1f678c5d0",
        "width": null,
        "height": null,
        "frame_index": null,
        "transformation_id": null,
        "coverage_notes": []
      },
      {
        "representation_id": "repr:otsu-threshold",
        "artifact_id": "artifact:scan-ed05d3f1b430:otsu-threshold",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:7fefd94afa741f129389ee52fd3a504fedc593d8b593d263ed4ace89fe7ddbe9",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:otsu-threshold",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:red-channel",
        "artifact_id": "artifact:scan-ed05d3f1b430:red-channel",
        "kind": "channel_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:b4e44611ae474450e002e5eab1f9808771851edbf58999ec1ab4f7a2aeafd54c",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:red-channel",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:sharpen-contrast",
        "artifact_id": "artifact:scan-ed05d3f1b430:sharpen-contrast",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:1818a100f04ce85382286e991a616507eb2701dcf41a084da58b77e8fc88c8bd",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:sharpen-contrast",
        "coverage_notes": []
      },
      {
        "representation_id": "repr:white-text-extract",
        "artifact_id": "artifact:scan-ed05d3f1b430:white-text-extract",
        "kind": "derived_view",
        "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "required_for_release": true,
        "release_relevant": true,
        "analyzed": true,
        "media_type": "image/png",
        "sha256": "sha256:662d79118a5025b0e22f8e8d3129508dee84e56d868008b2eebbbc9c6bc8beb7",
        "width": 640,
        "height": 240,
        "frame_index": null,
        "transformation_id": "transform:white-text-extract",
        "coverage_notes": []
      }
    ],
    "coverage_complete": true,
    "missing_required": []
  },
  "observations": [
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:000",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossy",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:canonical-lossy",
      "location": {
        "artifact_label": "release_candidate"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:001",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:canonical-lossless",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:canonical-lossless",
      "location": {
        "artifact_label": "canonical_lossless"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:002",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:flattened-white",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:flattened-white",
      "location": {
        "artifact_label": "flattened_white"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:003",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:flattened-black",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:flattened-black",
      "location": {
        "artifact_label": "flattened_black"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:004",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:grayscale",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:grayscale",
      "location": {
        "artifact_label": "grayscale"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:005",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:otsu-threshold",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:otsu-threshold",
      "location": {
        "artifact_label": "otsu-threshold"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:006",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:inverted-grayscale",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:inverted-grayscale",
      "location": {
        "artifact_label": "inverted-grayscale"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:007",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:red-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:red-channel",
      "location": {
        "artifact_label": "red-channel"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:008",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:green-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:green-channel",
      "location": {
        "artifact_label": "green-channel"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:009",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:blue-channel",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:blue-channel",
      "location": {
        "artifact_label": "blue-channel"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:010",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:2x-enlargement",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:2x-enlargement",
      "location": {
        "artifact_label": "2x-enlargement"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:011",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:white-text-extract",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:white-text-extract",
      "location": {
        "artifact_label": "white-text-extract"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:012",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:bg-normalised",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:bg-normalised",
      "location": {
        "artifact_label": "bg-normalised"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    },
    {
      "observation_id": "observation:scan-ed05d3f1b430:ocr:013",
      "source_artifact_id": "artifact:scan-ed05d3f1b430:sharpen-contrast",
      "source": "tesseract",
      "detector": "detector:tesseract",
      "classification": "ambiguous",
      "transformation": "transform:sharpen-contrast",
      "location": {
        "artifact_label": "sharpen-contrast"
      },
      "sha256": "sha256:fbf9dff91297f31b120623b4f48c024211fc563631409ca9c1704ab34ca5fc1f",
      "length": 58
    }
  ],
  "detector_executions": [
    {
      "detector_id": "detector:metadata-builtin",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "metadata",
      "category": "privacy",
      "required": true,
      "started_at": "2026-06-29T12:35:44.580819Z",
      "completed_at": "2026-06-29T12:35:44.581118Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:exiftool",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "metadata",
      "category": "privacy",
      "required": false,
      "started_at": "2026-06-29T12:35:44.581142Z",
      "completed_at": "2026-06-29T12:35:44.666624Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": "13.55"
    },
    {
      "detector_id": "detector:malware-clamav",
      "status": "ERROR",
      "state": "ERROR",
      "family": "malware",
      "category": "malware",
      "required": false,
      "started_at": "2026-06-29T12:35:44.666838Z",
      "completed_at": "2026-06-29T12:35:44.688412Z",
      "duration_ms": 11.71904100192478,
      "reason": "signature_database_missing",
      "tool_version": "ClamAV 1.5.2"
    },
    {
      "detector_id": "detector:malware-yara",
      "status": "ERROR",
      "state": "ERROR",
      "family": "malware",
      "category": "malware",
      "required": false,
      "started_at": "2026-06-29T12:35:44.688514Z",
      "completed_at": "2026-06-29T12:35:44.688569Z",
      "duration_ms": null,
      "reason": "yara_rule_bundle_missing",
      "tool_version": null
    },
    {
      "detector_id": "detector:embedded-binwalk",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "embedded_payload",
      "category": "embedded_payload",
      "required": false,
      "started_at": "2026-06-29T12:35:44.688584Z",
      "completed_at": "2026-06-29T12:35:44.704754Z",
      "duration_ms": 8.573084000090603,
      "reason": null,
      "tool_version": "Analyzes data for embedded file types"
    },
    {
      "detector_id": "detector:tesseract",
      "status": "SUCCESS",
      "state": "CONFIRMED",
      "family": "OCR",
      "category": "prompt_injection",
      "required": false,
      "started_at": "2026-06-29T12:35:44.705265Z",
      "completed_at": "2026-06-29T12:35:45.680929Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": "tesseract 5.5.2"
    },
    {
      "detector_id": "detector:qr-pyzbar",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "QR/barcode",
      "category": "embedded_payload",
      "required": false,
      "started_at": "2026-06-29T12:35:47.105014Z",
      "completed_at": "2026-06-29T12:35:47.105014Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:prompt-rules",
      "status": "SUCCESS",
      "state": "CONFIRMED",
      "family": "prompt",
      "category": "prompt_injection",
      "required": true,
      "started_at": "2026-06-29T12:35:47.105434Z",
      "completed_at": "2026-06-29T12:35:47.107741Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:semantic-scorer",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "prompt",
      "category": "prompt_injection",
      "required": false,
      "started_at": "2026-06-29T12:35:47.107746Z",
      "completed_at": "2026-06-29T12:35:47.107748Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:privacy-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "privacy",
      "category": "privacy",
      "required": false,
      "started_at": "2026-06-29T12:35:47.107752Z",
      "completed_at": "2026-06-29T12:35:47.107788Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:phishing-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "phishing",
      "category": "phishing",
      "required": false,
      "started_at": "2026-06-29T12:35:47.107791Z",
      "completed_at": "2026-06-29T12:35:47.107809Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    },
    {
      "detector_id": "detector:visible-watermark-rules",
      "status": "NO_EVIDENCE",
      "state": "NO_EVIDENCE_FOUND",
      "family": "watermarks",
      "category": "watermarks",
      "required": false,
      "started_at": "2026-06-29T12:35:47.107815Z",
      "completed_at": "2026-06-29T12:35:47.107815Z",
      "duration_ms": null,
      "reason": null,
      "tool_version": null
    }
  ],
  "release_grants": [],
  "coverage": {
    "original_container": "high",
    "all_frames": "complete",
    "visible_text": "medium",
    "low_contrast_text": "medium",
    "metadata_text": "medium",
    "known_embedded_formats": "low",
    "common_steganography": "low",
    "unknown_steganography": "low",
    "registered_watermark_schemes": "low",
    "unknown_watermarks": "unsupported",
    "model_specific_adversarial_attacks": "not_tested",
    "universal_attack_absence": "impossible",
    "universal_absence_claim": false
  },
  "module_status": {
    "artifact_store": {
      "name": "artifact_store",
      "status": "CONFIRMED",
      "reason": "/Users/lohith-uncovai/argus-eval-data/corpus/prompt_injection/data/argus.sqlite3",
      "version": null
    },
    "opencv_decoder": {
      "name": "opencv_decoder",
      "status": "CONFIRMED",
      "reason": null,
      "version": null
    },
    "release_candidate_decoder": {
      "name": "opencv_decoder",
      "status": "CONFIRMED",
      "reason": null,
      "version": null
    },
    "metadata_builtin": {
      "name": "metadata_builtin",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": null
    },
    "exiftool": {
      "name": "exiftool",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": "13.55"
    },
    "binwalk": {
      "name": "binwalk",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": "Analyzes data for embedded file types"
    },
    "clamav": {
      "name": "clamav",
      "status": "ERROR",
      "reason": "signature_database_missing",
      "version": "ClamAV 1.5.2"
    },
    "yara": {
      "name": "yara",
      "status": "ERROR",
      "reason": "yara_rule_bundle_missing",
      "version": null
    },
    "c2pa": {
      "name": "c2pa",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "paddleocr": {
      "name": "paddleocr",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "zsteg": {
      "name": "zsteg",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "embedded_thumbnails": {
      "name": "embedded_thumbnails",
      "status": "NO_EVIDENCE_FOUND",
      "reason": "no embedded thumbnails found",
      "version": null
    },
    "watermark_registry": {
      "name": "watermark_registry",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "redaction_analysis": {
      "name": "redaction_analysis",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "adversarial_stability": {
      "name": "adversarial_stability",
      "status": "NOT_TESTED",
      "reason": "skipped_by_mode",
      "version": null
    },
    "visual_analyzer": {
      "name": "visual_analyzer",
      "status": "NOT_TESTED",
      "reason": "NullVisualAnalyzer configured",
      "version": null
    },
    "tesseract": {
      "name": "tesseract",
      "status": "CONFIRMED",
      "reason": null,
      "version": "tesseract 5.5.2"
    },
    "qr": {
      "name": "qr",
      "status": "NO_EVIDENCE_FOUND",
      "reason": null,
      "version": null
    },
    "steganalysis_statistics": {
      "name": "steganalysis_statistics",
      "status": "CONFIRMED",
      "reason": "{'grayscale_entropy': 0.3332626951445209}",
      "version": null
    }
  },
  "limitations": [
    {
      "limitation_id": "limitation:universal-safety",
      "category": "global",
      "description": "No report can prove an image is universally safe."
    },
    {
      "limitation_id": "limitation:unknown-steganography",
      "category": "steganography",
      "description": "Arbitrary encrypted steganography cannot be excluded."
    },
    {
      "limitation_id": "limitation:unknown-watermarks",
      "category": "watermarks",
      "description": "Unknown watermark schemes are not exhaustively detectable."
    }
  ],
  "errors": [],
  "timings_ms": {
    "total_ms": 2715.4389999996056
  },
  "evidence_graph": {
    "nodes": [
      {
        "id": "artifact:scan-ed05d3f1b430:original",
        "type": "Artifact",
        "role": "original"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:canonical-lossy",
        "type": "Artifact",
        "role": "canonical_lossy"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "type": "Artifact",
        "role": "canonical_lossless"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:flattened-white",
        "type": "Artifact",
        "role": "flattened_white"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:flattened-black",
        "type": "Artifact",
        "role": "flattened_black"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:grayscale",
        "type": "Artifact",
        "role": "grayscale"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:otsu-threshold",
        "type": "Artifact",
        "role": "otsu-threshold"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:inverted-grayscale",
        "type": "Artifact",
        "role": "inverted-grayscale"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:red-channel",
        "type": "Artifact",
        "role": "red-channel"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:green-channel",
        "type": "Artifact",
        "role": "green-channel"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:blue-channel",
        "type": "Artifact",
        "role": "blue-channel"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:alpha-channel",
        "type": "Artifact",
        "role": "alpha-channel"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:2x-enlargement",
        "type": "Artifact",
        "role": "2x-enlargement"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:white-text-extract",
        "type": "Artifact",
        "role": "white-text-extract"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:bg-normalised",
        "type": "Artifact",
        "role": "bg-normalised"
      },
      {
        "id": "artifact:scan-ed05d3f1b430:sharpen-contrast",
        "type": "Artifact",
        "role": "sharpen-contrast"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:000",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:001",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:002",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:003",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:004",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:005",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:006",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:007",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:008",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:009",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:010",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:011",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:012",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "observation:scan-ed05d3f1b430:ocr:013",
        "type": "Observation",
        "detector": "detector:tesseract"
      },
      {
        "id": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "Finding",
        "category": "prompt_injection"
      }
    ],
    "edges": [
      {
        "from": "artifact:scan-ed05d3f1b430:original",
        "to": "artifact:scan-ed05d3f1b430:canonical-lossy",
        "type": "derived_from",
        "transformation": "transform:canonical-lossy"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:original",
        "to": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "type": "derived_from",
        "transformation": "transform:canonical-lossless"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:original",
        "to": "artifact:scan-ed05d3f1b430:flattened-white",
        "type": "derived_from",
        "transformation": "transform:flattened-white"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:original",
        "to": "artifact:scan-ed05d3f1b430:flattened-black",
        "type": "derived_from",
        "transformation": "transform:flattened-black"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:grayscale",
        "type": "derived_from",
        "transformation": "transform:grayscale"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:otsu-threshold",
        "type": "derived_from",
        "transformation": "transform:otsu-threshold"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:inverted-grayscale",
        "type": "derived_from",
        "transformation": "transform:inverted-grayscale"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:red-channel",
        "type": "derived_from",
        "transformation": "transform:red-channel"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:green-channel",
        "type": "derived_from",
        "transformation": "transform:green-channel"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:blue-channel",
        "type": "derived_from",
        "transformation": "transform:blue-channel"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:alpha-channel",
        "type": "derived_from",
        "transformation": "transform:alpha-channel"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:2x-enlargement",
        "type": "derived_from",
        "transformation": "transform:2x-enlargement"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:white-text-extract",
        "type": "derived_from",
        "transformation": "transform:white-text-extract"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:bg-normalised",
        "type": "derived_from",
        "transformation": "transform:bg-normalised"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "artifact:scan-ed05d3f1b430:sharpen-contrast",
        "type": "derived_from",
        "transformation": "transform:sharpen-contrast"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossy",
        "to": "observation:scan-ed05d3f1b430:ocr:000",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "observation:scan-ed05d3f1b430:ocr:001",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:flattened-white",
        "to": "observation:scan-ed05d3f1b430:ocr:002",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:flattened-black",
        "to": "observation:scan-ed05d3f1b430:ocr:003",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:grayscale",
        "to": "observation:scan-ed05d3f1b430:ocr:004",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:otsu-threshold",
        "to": "observation:scan-ed05d3f1b430:ocr:005",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:inverted-grayscale",
        "to": "observation:scan-ed05d3f1b430:ocr:006",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:red-channel",
        "to": "observation:scan-ed05d3f1b430:ocr:007",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:green-channel",
        "to": "observation:scan-ed05d3f1b430:ocr:008",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:blue-channel",
        "to": "observation:scan-ed05d3f1b430:ocr:009",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:2x-enlargement",
        "to": "observation:scan-ed05d3f1b430:ocr:010",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:white-text-extract",
        "to": "observation:scan-ed05d3f1b430:ocr:011",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:bg-normalised",
        "to": "observation:scan-ed05d3f1b430:ocr:012",
        "type": "observed_in"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:sharpen-contrast",
        "to": "observation:scan-ed05d3f1b430:ocr:013",
        "type": "observed_in"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:000",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:001",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:002",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:003",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:004",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:005",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:006",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:007",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:008",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:009",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:010",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:011",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:012",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "observation:scan-ed05d3f1b430:ocr:013",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:2x-enlargement",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:bg-normalised",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:blue-channel",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossless",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:canonical-lossy",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:flattened-black",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:flattened-white",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:grayscale",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:green-channel",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:inverted-grayscale",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:otsu-threshold",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:red-channel",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:sharpen-contrast",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      },
      {
        "from": "artifact:scan-ed05d3f1b430:white-text-extract",
        "to": "finding:scan-ed05d3f1b430:prompt:000",
        "type": "supports"
      }
    ]
  }
}
(argus-img) lohith-uncovai@Lohith-UncovAIs-MacBook-Pro prompt_injection % 


