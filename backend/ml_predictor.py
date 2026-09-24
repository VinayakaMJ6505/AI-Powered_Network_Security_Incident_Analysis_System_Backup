"""
AI-Powered Network Security Incident Analysis System

Module:
    ML Predictor

Purpose:
    Load the trained XGBoost model and classify network
    security incidents using the exact preprocessing objects
    saved with the trained model.

Model:
    XGBoost Multiclass Classifier

Input:
    UNSW-NB15 network-flow record

Output:
    Predicted attack category
    Confidence
    Class probabilities
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT /
    "final_network_security_xgboost.pkl"
)

TEST_DATA_PATH = (
    PROJECT_ROOT /
    "data" /
    "Training and Testing Sets" /
    "UNSW_NB15_testing-set.csv"
)


# ============================================================
# LOAD MODEL PACKAGE
# ============================================================

def load_model_package():
    """
    Load the trained model package.
    """

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            f"Model file not found:\n{MODEL_PATH}"
        )

    try:

        package = joblib.load(
            MODEL_PATH
        )

    except Exception as error:

        raise RuntimeError(
            "Unable to load the trained model package: "
            f"{error}"
        )

    if not isinstance(package, dict):

        raise ValueError(
            "The model package must be a dictionary."
        )

    required_keys = [
        "model",
        "encoder",
        "scaler",
        "categorical_columns",
        "numerical_columns",
        "label_encoder"
    ]

    missing_keys = [
        key
        for key in required_keys
        if key not in package
    ]

    if missing_keys:

        raise KeyError(
            "Model package is missing: "
            f"{missing_keys}"
        )

    return package


# ============================================================
# LOAD MODEL OBJECTS
# ============================================================

MODEL_PACKAGE = load_model_package()

MODEL = MODEL_PACKAGE["model"]

ENCODER = MODEL_PACKAGE["encoder"]

SCALER = MODEL_PACKAGE["scaler"]

CATEGORICAL_COLUMNS = list(
    MODEL_PACKAGE["categorical_columns"]
)

NUMERICAL_COLUMNS = list(
    MODEL_PACKAGE["numerical_columns"]
)

LABEL_ENCODER = MODEL_PACKAGE["label_encoder"]


# ============================================================
# MODEL FEATURES
# ============================================================

MODEL_FEATURES = (
    NUMERICAL_COLUMNS +
    CATEGORICAL_COLUMNS
)


# ============================================================
# MODEL INFORMATION
# ============================================================

def get_model_info():
    """
    Return information about the loaded model.
    """

    return {

        "model_type":
            type(MODEL).__name__,

        "number_of_classes":
            len(LABEL_ENCODER.classes_),

        "classes":
            [
                str(value)
                for value in LABEL_ENCODER.classes_
            ],

        "raw_numerical_features":
            len(NUMERICAL_COLUMNS),

        "raw_categorical_features":
            len(CATEGORICAL_COLUMNS),

        "total_raw_features":
            len(MODEL_FEATURES),

        "processed_features":
            int(MODEL.n_features_in_),

        "model_file":
            MODEL_PATH.name
    }


# ============================================================
# VALIDATE INPUT
# ============================================================

def validate_network_record(network_record):
    """
    Validate the raw network record before preprocessing.

    Returns:
        Dictionary containing validation details.
    """

    if not isinstance(
        network_record,
        dict
    ):

        raise TypeError(
            "network_record must be a dictionary."
        )

    # --------------------------------------------------------
    # Create DataFrame
    # --------------------------------------------------------

    input_df = pd.DataFrame(
        [network_record]
    )

    # --------------------------------------------------------
    # Remove optional fields
    # --------------------------------------------------------

    removable_columns = [
        "id",
        "attack_cat",
        "label"
    ]

    input_df = input_df.drop(
        columns=[
            column
            for column in removable_columns
            if column in input_df.columns
        ],
        errors="ignore"
    )

    # --------------------------------------------------------
    # Missing features
    # --------------------------------------------------------

    missing_features = [
        column
        for column in MODEL_FEATURES
        if column not in input_df.columns
    ]

    if missing_features:

        raise ValueError(
            "Missing required model features: "
            + ", ".join(missing_features)
        )

    # --------------------------------------------------------
    # Keep only model features
    # --------------------------------------------------------

    input_df = input_df[
        MODEL_FEATURES
    ].copy()

    # --------------------------------------------------------
    # Null values
    # --------------------------------------------------------

    null_features = []

    for column in MODEL_FEATURES:

        value = input_df.iloc[0][column]

        if pd.isna(value):

            null_features.append(
                column
            )

    if null_features:

        raise ValueError(
            "Null values found in model features: "
            + ", ".join(null_features)
        )

    # --------------------------------------------------------
    # Validate numerical features
    # --------------------------------------------------------

    invalid_numeric_features = []

    for column in NUMERICAL_COLUMNS:

        value = input_df.iloc[0][column]

        try:

            numeric_value = float(value)

            if not np.isfinite(
                numeric_value
            ):

                invalid_numeric_features.append(
                    column
                )

        except (
            TypeError,
            ValueError
        ):

            invalid_numeric_features.append(
                column
            )

    if invalid_numeric_features:

        raise ValueError(
            "Invalid numerical values found in: "
            + ", ".join(
                invalid_numeric_features
            )
        )

    # --------------------------------------------------------
    # Validate categorical values
    # --------------------------------------------------------

    invalid_categorical_features = []

    for column in CATEGORICAL_COLUMNS:

        value = input_df.iloc[0][column]

        if value is None:

            invalid_categorical_features.append(
                column
            )

    if invalid_categorical_features:

        raise ValueError(
            "Invalid categorical values found in: "
            + ", ".join(
                invalid_categorical_features
            )
        )

    return {
        "valid": True,
        "missing_features": [],
        "null_features": [],
        "invalid_numeric_features": [],
        "invalid_categorical_features": []
    }


# ============================================================
# PREPARE INPUT
# ============================================================

def prepare_input(network_record):
    """
    Prepare one raw UNSW-NB15 record for XGBoost.

    IMPORTANT:
        The frontend must send raw values.

        The backend applies:
            OneHotEncoder
            StandardScaler
    """

    if not isinstance(
        network_record,
        dict
    ):

        raise TypeError(
            "network_record must be a dictionary."
        )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    validate_network_record(
        network_record
    )

    # --------------------------------------------------------
    # Create DataFrame
    # --------------------------------------------------------

    input_df = pd.DataFrame(
        [network_record]
    )

    # --------------------------------------------------------
    # Remove non-model columns
    # --------------------------------------------------------

    input_df = input_df.drop(
        columns=[
            column
            for column in [
                "id",
                "attack_cat",
                "label"
            ]
            if column in input_df.columns
        ],
        errors="ignore"
    )

    # --------------------------------------------------------
    # Keep exact model feature order
    # --------------------------------------------------------

    input_df = input_df[
        MODEL_FEATURES
    ].copy()

    # --------------------------------------------------------
    # Convert numerical values
    # --------------------------------------------------------

    for column in NUMERICAL_COLUMNS:

        input_df[column] = pd.to_numeric(
            input_df[column],
            errors="raise"
        )

    # --------------------------------------------------------
    # Categorical values
    # --------------------------------------------------------

    for column in CATEGORICAL_COLUMNS:

        input_df[column] = (
            input_df[column]
            .astype(str)
        )

    # --------------------------------------------------------
    # OneHotEncoder
    # --------------------------------------------------------

    categorical_data = (
        ENCODER.transform(
            input_df[
                CATEGORICAL_COLUMNS
            ]
        )
    )

    # --------------------------------------------------------
    # StandardScaler
    # --------------------------------------------------------

    numerical_data = (
        SCALER.transform(
            input_df[
                NUMERICAL_COLUMNS
            ]
        )
    )

    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    processed_input = np.hstack(
        [
            numerical_data,
            categorical_data
        ]
    )

    # --------------------------------------------------------
    # Feature count verification
    # --------------------------------------------------------

    expected_features = (
        MODEL.n_features_in_
    )

    actual_features = (
        processed_input.shape[1]
    )

    if actual_features != expected_features:

        raise ValueError(
            "Processed feature count mismatch. "
            f"Expected {expected_features}, "
            f"received {actual_features}."
        )

    return processed_input


# ============================================================
# PREDICT ATTACK
# ============================================================

def predict_attack(network_record):
    """
    Predict attack category.

    Returns:
        predicted_attack
        confidence
        probabilities
    """

    processed_input = prepare_input(
        network_record
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    predicted_encoded = (
        MODEL.predict(
            processed_input
        )[0]
    )

    predicted_attack = (
        LABEL_ENCODER.inverse_transform(
            [
                int(
                    predicted_encoded
                )
            ]
        )[0]
    )

    # --------------------------------------------------------
    # Probabilities
    # --------------------------------------------------------

    probability_values = (
        MODEL.predict_proba(
            processed_input
        )[0]
    )

    class_names = (
        LABEL_ENCODER.classes_
    )

    probabilities = {

        str(class_names[index]):
            round(
                float(probability),
                4
            )

        for index, probability
        in enumerate(
            probability_values
        )
    }

    confidence = round(
        float(
            np.max(
                probability_values
            )
        ),
        4
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {

        "predicted_attack":
            str(predicted_attack),

        "confidence":
            confidence,

        "probabilities":
            probabilities
    }


# ============================================================
# DATASET TEST
# ============================================================

def test_with_dataset_record(
    row_number=0
):
    """
    Test the trained model using one
    UNSW-NB15 testing record.
    """

    if not TEST_DATA_PATH.exists():

        raise FileNotFoundError(
            "Testing dataset not found:\n"
            f"{TEST_DATA_PATH}"
        )

    test_df = pd.read_csv(
        TEST_DATA_PATH
    )

    if test_df.empty:

        raise ValueError(
            "Testing dataset is empty."
        )

    if row_number < 0 or row_number >= len(test_df):

        raise IndexError(
            f"Row number must be between "
            f"0 and {len(test_df) - 1}."
        )

    row = test_df.iloc[
        row_number
    ]

    record = row.to_dict()

    actual_attack = record.get(
        "attack_cat"
    )

    actual_label = record.get(
        "label"
    )

    result = predict_attack(
        record
    )

    print()
    print("=" * 70)
    print("UNSW-NB15 MODEL TEST")
    print("=" * 70)

    print(
        "Dataset Row      :",
        row_number + 1
    )

    print(
        "Actual Attack     :",
        actual_attack
    )

    print(
        "Actual Label      :",
        actual_label
    )

    print(
        "Predicted Attack  :",
        result["predicted_attack"]
    )

    print(
        "Confidence        :",
        result["confidence"]
    )

    print()

    print("Probabilities")
    print("-" * 50)

    for attack, probability in (
        result["probabilities"].items()
    ):

        print(
            f"{attack:18} : "
            f"{probability}"
        )

    print("=" * 70)

    return {
        "actual_attack":
            actual_attack,

        "actual_label":
            actual_label,

        "prediction":
            result
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print(
        "AI-POWERED NETWORK SECURITY "
        "INCIDENT ANALYSIS SYSTEM"
    )
    print("XGBOOST ML PREDICTOR")
    print("=" * 70)

    print()

    print(
        get_model_info()
    )

    test_with_dataset_record()