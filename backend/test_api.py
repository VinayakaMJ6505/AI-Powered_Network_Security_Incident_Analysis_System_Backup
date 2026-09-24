import json

import pandas as pd

from urllib.request import (
    Request,
    urlopen
)

from urllib.error import (
    HTTPError,
    URLError
)

from ml_predictor import (
    TEST_DATA_PATH
)


API_URL = (
    "http://127.0.0.1:8000/api/analyze"
)


# ============================================================
# CONVERT VALUES
# ============================================================

def convert_value(value):

    if pd.isna(value):

        return None

    if hasattr(
        value,
        "item"
    ):

        return value.item()

    return value


# ============================================================
# LOAD DATASET RECORD
# ============================================================

def load_test_record(
    row_number=0
):

    print(
        "Loading UNSW-NB15 testing dataset..."
    )

    print(
        f"Dataset: {TEST_DATA_PATH}"
    )

    test_df = pd.read_csv(
        TEST_DATA_PATH
    )

    if test_df.empty:

        raise ValueError(
            "Testing dataset is empty."
        )

    if row_number < 0:

        raise ValueError(
            "Row number cannot be negative."
        )

    if row_number >= len(test_df):

        raise ValueError(
            f"Row number exceeds dataset. "
            f"Maximum: {len(test_df) - 1}"
        )

    row = test_df.iloc[
        row_number
    ]

    actual_attack = row.get(
        "attack_cat"
    )

    actual_label = row.get(
        "label"
    )

    dataset_id = row.get(
        "id"
    )

    network_record = (
        row.drop(
            labels=[
                "attack_cat",
                "label"
            ],
            errors="ignore"
        )
        .to_dict()
    )

    network_record = {

        key:
            convert_value(value)

        for key, value
        in network_record.items()
    }

    return (
        network_record,
        actual_attack,
        actual_label,
        dataset_id
    )


# ============================================================
# SEND REQUEST
# ============================================================

def send_request(
    network_record,
    actual_attack,
    actual_label,
    dataset_id
):

    security_log = (
        f"UNSW-NB15 network traffic record "
        f"{dataset_id} submitted for "
        f"security incident analysis."
    )

    request_body = {

        "security_log":
            security_log,

        "network_record":
            network_record,

        "dataset_id":
            int(dataset_id)
            if dataset_id is not None
            else None,

        "ground_truth_attack":
            str(actual_attack)
            if actual_attack is not None
            else None,

        "ground_truth_label":
            int(actual_label)
            if actual_label is not None
            else None
    }

    json_data = json.dumps(
        request_body
    ).encode("utf-8")

    request = Request(

        API_URL,

        data=json_data,

        headers={
            "Content-Type":
                "application/json"
        },

        method="POST"
    )

    print()
    print(
        "Sending request to FastAPI..."
    )

    try:

        with urlopen(
            request
        ) as response:

            body = (
                response
                .read()
                .decode("utf-8")
            )

            return (
                response.status,
                json.loads(body)
            )

    except HTTPError as error:

        body = (
            error
            .read()
            .decode("utf-8")
        )

        print(
            f"HTTP Error: {error.code}"
        )

        print(body)

        return (
            error.code,
            None
        )

    except URLError as error:

        print(
            "Could not connect to FastAPI."
        )

        print(
            error.reason
        )

        return (
            None,
            None
        )


# ============================================================
# DISPLAY
# ============================================================

def display_result(
    status,
    response
):

    print()
    print("=" * 70)
    print(
        "AI NETWORK SECURITY INCIDENT ANALYSIS"
    )
    print("=" * 70)

    print(
        "HTTP Status:",
        status
    )

    if response is None:

        return

    print()

    print(
        json.dumps(
            response,
            indent=4
        )
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print(
        "FASTAPI END-TO-END TEST"
    )
    print("=" * 70)

    (
        network_record,
        actual_attack,
        actual_label,
        dataset_id
    ) = load_test_record(
        row_number=0
    )

    print()
    print(
        "Dataset ID:",
        dataset_id
    )

    print(
        "Ground Truth:",
        actual_attack
    )

    print(
        "Binary Label:",
        actual_label
    )

    print(
        "Model Features:",
        len(network_record)
    )

    status, response = send_request(

        network_record,

        actual_attack,

        actual_label,

        dataset_id
    )

    display_result(
        status,
        response
    )


if __name__ == "__main__":

    main()