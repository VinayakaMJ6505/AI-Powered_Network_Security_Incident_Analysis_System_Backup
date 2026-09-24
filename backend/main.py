from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .database import (
    initialize_database,
    get_dashboard_statistics,
    get_all_incidents,
    get_incident_by_id,
    save_incident,
)

from .incident_analyzer import analyze_incident

from .genai_analyzer import (
    generate_incident_explanation
)

from .ml_predictor import (
    TEST_DATA_PATH,
    get_model_info,
)

from .nlp_analyzer import (
    analyze_security_log
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AI-Powered Network Security Incident Analysis System",
    description=(
        "AI-powered network security incident analysis "
        "using XGBoost, NLP and risk assessment."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ============================================================
# MODEL FEATURES
# ============================================================

MODEL_FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
    "proto",
    "service",
    "state",
]


CATEGORICAL_FEATURES = [
    "proto",
    "service",
    "state",
]


NUMERICAL_FEATURES = [
    feature
    for feature in MODEL_FEATURES
    if feature not in CATEGORICAL_FEATURES
]


# ============================================================
# REQUEST MODELS
# ============================================================

class IncidentRequest(BaseModel):

    security_log: str = Field(
        ...,
        min_length=1,
        description="Security log to analyze.",
    )

    network_record: Dict[str, Any] = Field(
        ...,
        description=(
            "UNSW-NB15 network record containing "
            "the 42 model features."
        ),
    )

    dataset_id: Optional[int] = Field(
        default=None,
        description="Dataset record ID.",
    )

    ground_truth_attack: Optional[str] = Field(
        default=None,
        description="Actual UNSW-NB15 attack category.",
    )

    ground_truth_label: Optional[int] = Field(
        default=None,
        description="Actual UNSW-NB15 binary label.",
    )


class SecurityLogRequest(BaseModel):

    log: str = Field(
        ...,
        min_length=1,
        description="Raw security log text.",
    )


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():

    initialize_database()

    print("=" * 70)
    print(
        "AI-Powered Network Security "
        "Incident Analysis System"
    )
    print("=" * 70)

    print(
        "FastAPI server started successfully"
    )

    print(
        "API Documentation : "
        "http://127.0.0.1:8000/docs"
    )

    print(
        "Health Check      : "
        "http://127.0.0.1:8000/api/health"
    )

    print(
        "Model Information : "
        "http://127.0.0.1:8000/api/model"
    )

    print(
        "Dataset Information : "
        "http://127.0.0.1:8000/api/dataset/info"
    )

    print("=" * 70)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "success": True,

        "message": (
            "AI-Powered Network Security "
            "Incident Analysis System API"
        ),

        "version": "1.0.0",

        "docs": "/docs",

        "endpoints": {
            "health": "/api/health",
            "model": "/api/model",
            "dataset_info": "/api/dataset/info",
            "dataset_record":
                "/api/dataset/record/{record_number}",
            "analyze": "/api/analyze",
            "logs_analyze": "/api/logs/analyze",
            "incidents": "/api/incidents",
            "incident_by_id": "/api/incidents/{id}",
            "dashboard": "/api/dashboard",
        },
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
async def health_check():

    return {
        "success": True,
        "status": "healthy",
        "message": (
            "Network Security Incident "
            "Analysis API is running"
        ),
    }


# ============================================================
# MODEL INFORMATION
# ============================================================

@app.get("/api/model")
async def model_information():

    try:

        model_info = get_model_info()

        return {
            "success": True,
            "data": model_info,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve model information: "
                f"{str(error)}"
            ),
        )


# ============================================================
# DATASET LOADER
# ============================================================

@lru_cache(maxsize=1)
def load_testing_dataset():

    if not TEST_DATA_PATH.exists():

        raise FileNotFoundError(
            "UNSW-NB15 testing dataset was not found:\n"
            f"{TEST_DATA_PATH}"
        )

    dataframe = pd.read_csv(
        TEST_DATA_PATH
    )

    if dataframe.empty:

        raise ValueError(
            "UNSW-NB15 testing dataset is empty."
        )

    return dataframe


# ============================================================
# DATASET INFORMATION
# ============================================================

@app.get("/api/dataset/info")
async def dataset_information():

    try:

        dataframe = load_testing_dataset()

        attack_distribution = {}

        if "attack_cat" in dataframe.columns:

            attack_distribution = {
                str(key): int(value)
                for key, value
                in dataframe[
                    "attack_cat"
                ].value_counts().items()
            }

        return {

            "success": True,

            "data": {

                "dataset_name":
                    TEST_DATA_PATH.name,

                "total_records":
                    int(len(dataframe)),

                "total_columns":
                    int(len(dataframe.columns)),

                "model_features":
                    len(MODEL_FEATURES),

                "categorical_features":
                    CATEGORICAL_FEATURES,

                "numerical_features":
                    NUMERICAL_FEATURES,

                "attack_distribution":
                    attack_distribution,
            },
        }

    except FileNotFoundError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to read testing dataset: "
                f"{str(error)}"
            ),
        )


# ============================================================
# GENERATED NETWORK SECURITY LOG
# ============================================================

def build_network_security_log(
    row: pd.Series
) -> str:
    """
    Generate a structured, NLP-readable network
    security log from an UNSW-NB15 record.

    Only information actually available in the
    dataset is included.

    IP addresses, ports and usernames are not
    fabricated because they are not part of the
    42 model features.
    """

    def get_value(
        column: str,
        default: str = "N/A"
    ):

        value = row.get(
            column,
            default
        )

        if pd.isna(value):

            return default

        value = str(value).strip()

        if not value:

            return default

        if value.lower() in {
            "nan",
            "none",
            "null",
        }:

            return default

        return value


    def get_number(
        column: str,
        default: float = 0.0
    ):

        value = row.get(
            column,
            default
        )

        try:

            if pd.isna(value):

                return default

            return float(value)

        except (
            TypeError,
            ValueError
        ):

            return default


    def fmt(
        value: float,
        decimals: int = 6
    ):

        return (
            f"{value:.{decimals}f}"
        )


    # --------------------------------------------------------
    # BASIC NETWORK INFORMATION
    # --------------------------------------------------------

    record_id = get_value(
        "id"
    )

    protocol = get_value(
        "proto",
        "unknown"
    ).upper()

    service = get_value(
        "service",
        "unknown"
    )

    state = get_value(
        "state",
        "unknown"
    )


    # --------------------------------------------------------
    # TRAFFIC INFORMATION
    # --------------------------------------------------------

    duration = get_number(
        "dur"
    )

    source_packets = get_number(
        "spkts"
    )

    destination_packets = get_number(
        "dpkts"
    )

    source_bytes = get_number(
        "sbytes"
    )

    destination_bytes = get_number(
        "dbytes"
    )

    traffic_rate = get_number(
        "rate"
    )


    # --------------------------------------------------------
    # TTL
    # --------------------------------------------------------

    source_ttl = get_number(
        "sttl"
    )

    destination_ttl = get_number(
        "dttl"
    )


    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    source_load = get_number(
        "sload"
    )

    destination_load = get_number(
        "dload"
    )


    # --------------------------------------------------------
    # LOSS
    # --------------------------------------------------------

    source_loss = get_number(
        "sloss"
    )

    destination_loss = get_number(
        "dloss"
    )


    # --------------------------------------------------------
    # TIMING
    # --------------------------------------------------------

    source_packet_interval = get_number(
        "sinpkt"
    )

    destination_packet_interval = get_number(
        "dinpkt"
    )

    source_jitter = get_number(
        "sjit"
    )

    destination_jitter = get_number(
        "djit"
    )


    # --------------------------------------------------------
    # PACKET SIZE
    # --------------------------------------------------------

    source_mean = get_number(
        "smean"
    )

    destination_mean = get_number(
        "dmean"
    )


    # --------------------------------------------------------
    # CONNECTION COUNTS
    # --------------------------------------------------------

    service_source_count = get_number(
        "ct_srv_src"
    )

    state_ttl_count = get_number(
        "ct_state_ttl"
    )

    destination_ltm = get_number(
        "ct_dst_ltm"
    )

    source_port_ltm = get_number(
        "ct_src_dport_ltm"
    )

    destination_port_ltm = get_number(
        "ct_dst_sport_ltm"
    )

    destination_source_ltm = get_number(
        "ct_dst_src_ltm"
    )


    # --------------------------------------------------------
    # APPLICATION FEATURES
    # --------------------------------------------------------

    ftp_login = get_number(
        "is_ftp_login"
    )

    ftp_commands = get_number(
        "ct_ftp_cmd"
    )

    http_methods = get_number(
        "ct_flw_http_mthd"
    )


    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # --------------------------------------------------------
    # LOG
    # --------------------------------------------------------

    return (

        f"{timestamp} | "

        f"UNSW-NB15 network flow record "
        f"{record_id} | "

        f"Protocol: {protocol} | "

        f"Service: {service} | "

        f"Connection State: {state} | "

        f"Duration: "
        f"{fmt(duration)} seconds | "

        f"Source Packets: "
        f"{source_packets:g} | "

        f"Destination Packets: "
        f"{destination_packets:g} | "

        f"Source Bytes: "
        f"{source_bytes:g} | "

        f"Destination Bytes: "
        f"{destination_bytes:g} | "

        f"Traffic Rate: "
        f"{fmt(traffic_rate)} | "

        f"Source TTL: "
        f"{source_ttl:g} | "

        f"Destination TTL: "
        f"{destination_ttl:g} | "

        f"Source Load: "
        f"{fmt(source_load)} | "

        f"Destination Load: "
        f"{fmt(destination_load)} | "

        f"Source Loss: "
        f"{source_loss:g} | "

        f"Destination Loss: "
        f"{destination_loss:g} | "

        f"Source Packet Interval: "
        f"{fmt(source_packet_interval)} | "

        f"Destination Packet Interval: "
        f"{fmt(destination_packet_interval)} | "

        f"Source Jitter: "
        f"{fmt(source_jitter)} | "

        f"Destination Jitter: "
        f"{fmt(destination_jitter)} | "

        f"Source Mean Packet Size: "
        f"{source_mean:g} | "

        f"Destination Mean Packet Size: "
        f"{destination_mean:g} | "

        f"Service-Source Count: "
        f"{service_source_count:g} | "

        f"State-TTL Count: "
        f"{state_ttl_count:g} | "

        f"Destination LTM Count: "
        f"{destination_ltm:g} | "

        f"Source-Port LTM Count: "
        f"{source_port_ltm:g} | "

        f"Destination-Port LTM Count: "
        f"{destination_port_ltm:g} | "

        f"Destination-Source LTM Count: "
        f"{destination_source_ltm:g} | "

        f"FTP Login Flag: "
        f"{ftp_login:g} | "

        f"FTP Command Count: "
        f"{ftp_commands:g} | "

        f"HTTP Method Count: "
        f"{http_methods:g} | "

        "Source and destination IP addresses "
        "and transport ports are not included "
        "in this UNSW-NB15 model record."
    )


# ============================================================
# GET ONE DATASET RECORD
# ============================================================

@app.get(
    "/api/dataset/record/{record_number}"
)
async def get_dataset_record(
    record_number: int
):

    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if record_number < 1:

        raise HTTPException(
            status_code=400,
            detail=(
                "Record number must be "
                "greater than or equal to 1."
            ),
        )


    try:

        dataframe = (
            load_testing_dataset()
        )


        total_records = len(
            dataframe
        )


        # ----------------------------------------------------
        # RANGE VALIDATION
        # ----------------------------------------------------

        if record_number > total_records:

            raise HTTPException(
                status_code=404,
                detail=(
                    f"Record number {record_number} "
                    f"does not exist. "
                    f"Valid range: "
                    f"1-{total_records}."
                ),
            )


        # ----------------------------------------------------
        # GET DATASET ROW
        # ----------------------------------------------------

        row = dataframe.iloc[
            record_number - 1
        ]


        # ----------------------------------------------------
        # DATASET ID
        # ----------------------------------------------------

        dataset_id = row.get(
            "id"
        )


        if pd.isna(
            dataset_id
        ):

            dataset_id = None

        else:

            dataset_id = int(
                dataset_id
            )


        # ----------------------------------------------------
        # GROUND TRUTH ATTACK
        # ----------------------------------------------------

        ground_truth_attack = row.get(
            "attack_cat"
        )


        if pd.isna(
            ground_truth_attack
        ):

            ground_truth_attack = None

        else:

            ground_truth_attack = str(
                ground_truth_attack
            ).strip()


        # ----------------------------------------------------
        # GROUND TRUTH LABEL
        # ----------------------------------------------------

        ground_truth_label = row.get(
            "label"
        )


        if pd.isna(
            ground_truth_label
        ):

            ground_truth_label = None

        else:

            ground_truth_label = int(
                ground_truth_label
            )


        # ----------------------------------------------------
        # BUILD EXACT 42-FEATURE MODEL RECORD
        # ----------------------------------------------------

        network_record = {}


        for feature in MODEL_FEATURES:

            if feature not in dataframe.columns:

                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Dataset is missing required "
                        f"model feature: {feature}"
                    ),
                )


            value = row[
                feature
            ]


            # ------------------------------------------------
            # CATEGORICAL
            # ------------------------------------------------

            if feature in CATEGORICAL_FEATURES:

                if pd.isna(value):

                    value = "-"

                else:

                    value = str(
                        value
                    ).strip()

                    if not value:

                        value = "-"


                network_record[
                    feature
                ] = value


            # ------------------------------------------------
            # NUMERICAL
            # ------------------------------------------------

            else:

                try:

                    numeric_value = float(
                        value
                    )

                    if not np.isfinite(
                        numeric_value
                    ):

                        numeric_value = 0.0

                except (
                    TypeError,
                    ValueError
                ):

                    numeric_value = 0.0


                network_record[
                    feature
                ] = numeric_value


        # ----------------------------------------------------
        # GENERATED SECURITY LOG
        # ----------------------------------------------------

        security_log = (
            build_network_security_log(
                row
            )
        )


        # ----------------------------------------------------
        # RAW RECORD
        # ----------------------------------------------------

        raw_record = {}


        for column in dataframe.columns:

            value = row[
                column
            ]


            if pd.isna(value):

                raw_record[
                    column
                ] = None

            elif isinstance(
                value,
                np.integer
            ):

                raw_record[
                    column
                ] = int(value)

            elif isinstance(
                value,
                np.floating
            ):

                raw_record[
                    column
                ] = float(value)

            else:

                raw_record[
                    column
                ] = value


        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "success": True,

            "record_number":
                record_number,

            "total_records":
                total_records,

            "dataset_id":
                dataset_id,

            "ground_truth_attack":
                ground_truth_attack,

            "ground_truth_label":
                ground_truth_label,

            "network_record":
                network_record,

            "security_log":
                security_log,

            "raw_record":
                raw_record,
        }


    except HTTPException:

        raise


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load dataset record: "
                f"{str(error)}"
            ),
        )


# ============================================================
# NLP LOG ANALYSIS
# ============================================================

@app.post(
    "/api/logs/analyze"
)
async def analyze_security_log_endpoint(
    request: SecurityLogRequest
):

    try:

        result = analyze_security_log(
            request.log
        )

        return {

            "success": True,

            "data": result,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Security log analysis failed: "
                f"{str(error)}"
            ),
        )


# ============================================================
# FULL INCIDENT ANALYSIS
# ============================================================

@app.post(
    "/api/analyze"
)
async def analyze_incident_endpoint(
    request: IncidentRequest
):

    try:

        # ----------------------------------------------------
        # NLP + ML + RISK
        # ----------------------------------------------------

        analysis_result = (
            analyze_incident(
                security_log=
                    request.security_log,

                network_record=
                    request.network_record,
            )
        )


        # ----------------------------------------------------
        # ML PREDICTION
        # ----------------------------------------------------

        ml_prediction = (
            analysis_result.get(
                "ml_prediction",
                {}
            )
        )


        predicted_attack = (
            ml_prediction.get(
                "predicted_attack"
            )
        )


        # ----------------------------------------------------
        # GROUND TRUTH VALIDATION
        # ----------------------------------------------------

        prediction_correct = None


        if (
            request.ground_truth_attack
            is not None
            and predicted_attack
            is not None
        ):

            prediction_correct = (

                str(
                    predicted_attack
                ).strip().lower()

                ==

                str(
                    request.ground_truth_attack
                ).strip().lower()

            )


        dataset_validation = {

            "dataset_id":
                request.dataset_id,

            "ground_truth_attack":
                request.ground_truth_attack,

            "ground_truth_label":
                request.ground_truth_label,

            "predicted_attack":
                predicted_attack,

            "prediction_correct":
                prediction_correct,

            "status":

                "CORRECT"
                if prediction_correct is True

                else

                "INCORRECT"
                if prediction_correct is False

                else

                "NOT_VALIDATED",
        }


        # ----------------------------------------------------
        # INCIDENT EXPLANATION
        # ----------------------------------------------------

        explanation = (
            generate_incident_explanation(
                analysis_result
            )
        )


        # ----------------------------------------------------
        # SAVE INCIDENT
        # ----------------------------------------------------

        incident_id = save_incident(

            incident_result=
                analysis_result,

            explanation=
                explanation,

            dataset_validation=
                dataset_validation,

        )


        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "success": True,

            "message": (
                "Security incident analyzed "
                "and stored successfully."
            ),

            "data": {

                "incident_id":
                    incident_id,

                "incident":
                    analysis_result,

                "explanation":
                    explanation,

                "dataset_validation":
                    dataset_validation,

                "saved_incident":
                    {
                        "id":
                            incident_id
                    },
            },
        }


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Incident analysis failed: "
                f"{str(error)}"
            ),
        )


# ============================================================
# ALL INCIDENTS
# ============================================================

@app.get(
    "/api/incidents"
)
async def get_incidents_endpoint():

    try:

        incidents = (
            get_all_incidents()
        )

        return {

            "success": True,

            "count":
                len(incidents),

            "data":
                incidents,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve incidents: "
                f"{str(error)}"
            ),
        )


# ============================================================
# INCIDENT BY ID
# ============================================================

@app.get(
    "/api/incidents/{incident_id}"
)
async def get_incident_endpoint(
    incident_id: int
):

    try:

        incident = (
            get_incident_by_id(
                incident_id
            )
        )


        if incident is None:

            raise HTTPException(
                status_code=404,
                detail=(
                    f"Incident {incident_id} "
                    "not found."
                ),
            )


        return {

            "success": True,

            "data":
                incident,
        }


    except HTTPException:

        raise


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve incident: "
                f"{str(error)}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/api/dashboard"
)
async def dashboard_statistics():

    try:

        statistics = (
            get_dashboard_statistics()
        )

        return {

            "success": True,

            "data":
                statistics,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve dashboard "
                f"statistics: {str(error)}"
            ),
        )