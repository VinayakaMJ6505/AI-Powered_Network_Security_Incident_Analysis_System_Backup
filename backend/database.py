"""
AI-Powered Network Security Incident Analysis System

Module:
    Database

Database:
    SQLite

Stores:
    NLP analysis
    ML prediction
    Risk analysis
    Dataset validation
    Incident explanation
"""


import sqlite3

from pathlib import Path

from datetime import datetime


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

DATABASE_PATH = (
    PROJECT_ROOT /
    "security_incidents.db"
)


# ============================================================
# CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            security_log TEXT NOT NULL,

            dataset_id INTEGER,

            ground_truth_attack TEXT,

            ground_truth_label INTEGER,

            prediction_correct INTEGER,

            ip_address TEXT,

            protocol TEXT,

            port INTEGER,

            detected_event TEXT,

            nlp_severity TEXT,

            predicted_attack TEXT,

            confidence REAL,

            base_risk REAL,

            risk_score REAL,

            risk_severity TEXT,

            incident_summary TEXT,

            technical_explanation TEXT,

            recommended_actions TEXT,

            created_at TEXT NOT NULL
        )
        """
    )

    connection.commit()

    # --------------------------------------------------------
    # Database migration
    # --------------------------------------------------------

    existing_columns = {
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(incidents)"
        ).fetchall()
    }

    migrations = {

        "dataset_id":
            "ALTER TABLE incidents ADD COLUMN dataset_id INTEGER",

        "ground_truth_attack":
            "ALTER TABLE incidents ADD COLUMN ground_truth_attack TEXT",

        "ground_truth_label":
            "ALTER TABLE incidents ADD COLUMN ground_truth_label INTEGER",

        "prediction_correct":
            "ALTER TABLE incidents ADD COLUMN prediction_correct INTEGER"
    }

    for column, sql in migrations.items():

        if column not in existing_columns:

            cursor.execute(sql)

    connection.commit()

    connection.close()


# ============================================================
# SAVE INCIDENT
# ============================================================

def save_incident(
    incident_result,
    explanation,
    dataset_validation=None
):

    if dataset_validation is None:

        dataset_validation = {}

    nlp_analysis = incident_result.get(
        "nlp_analysis",
        {}
    )

    ml_prediction = incident_result.get(
        "ml_prediction",
        {}
    )

    risk_analysis = incident_result.get(
        "risk_analysis",
        {}
    )

    recommended_actions = (
        explanation.get(
            "recommended_actions",
            []
        )
    )

    recommended_actions_text = "\n".join(
        f"- {action}"
        for action in recommended_actions
    )

    created_at = datetime.now().isoformat(
        timespec="seconds"
    )

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO incidents (

            security_log,

            dataset_id,
            ground_truth_attack,
            ground_truth_label,
            prediction_correct,

            ip_address,
            protocol,
            port,

            detected_event,
            nlp_severity,

            predicted_attack,
            confidence,

            base_risk,
            risk_score,
            risk_severity,

            incident_summary,
            technical_explanation,

            recommended_actions,

            created_at
        )

        VALUES (
            ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?,
            ?
        )
        """,

        (

            incident_result.get(
                "security_log"
            ),

            dataset_validation.get(
                "dataset_id"
            ),

            dataset_validation.get(
                "ground_truth_attack"
            ),

            dataset_validation.get(
                "ground_truth_label"
            ),

            dataset_validation.get(
                "prediction_correct"
            ),

            nlp_analysis.get(
                "ip_address"
            ),

            nlp_analysis.get(
                "protocol"
            ),

            nlp_analysis.get(
                "port"
            ),

            nlp_analysis.get(
                "event"
            ),

            nlp_analysis.get(
                "severity"
            ),

            ml_prediction.get(
                "predicted_attack"
            ),

            ml_prediction.get(
                "confidence"
            ),

            risk_analysis.get(
                "base_risk"
            ),

            risk_analysis.get(
                "risk_score"
            ),

            risk_analysis.get(
                "severity"
            ),

            explanation.get(
                "incident_summary"
            ),

            explanation.get(
                "technical_explanation"
            ),

            recommended_actions_text,

            created_at
        )
    )

    incident_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return incident_id


# ============================================================
# GET ALL INCIDENTS
# ============================================================

def get_all_incidents():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    incidents = [
        dict(row)
        for row in rows
    ]

    connection.close()

    return incidents


# ============================================================
# GET INCIDENT BY ID
# ============================================================

def get_incident_by_id(
    incident_id
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        WHERE id = ?
        """,
        (incident_id,)
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:

        return None

    return dict(row)


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_statistics():

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------------
    # Total
    # --------------------------------------------------------

    cursor.execute(
        "SELECT COUNT(*) FROM incidents"
    )

    total_incidents = (
        cursor.fetchone()[0]
    )

    # --------------------------------------------------------
    # Attack distribution
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            predicted_attack,
            COUNT(*) AS count

        FROM incidents

        GROUP BY predicted_attack

        ORDER BY count DESC
        """
    )

    attack_distribution = {

        row["predicted_attack"]:
            row["count"]

        for row in cursor.fetchall()
    }

    # --------------------------------------------------------
    # Severity distribution
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            risk_severity,
            COUNT(*) AS count

        FROM incidents

        GROUP BY risk_severity
        """
    )

    severity_distribution = {

        row["risk_severity"]:
            row["count"]

        for row in cursor.fetchall()
    }

    # --------------------------------------------------------
    # Average risk
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT AVG(risk_score)
        FROM incidents
        """
    )

    average_risk_score = (
        cursor.fetchone()[0]
    )

    # --------------------------------------------------------
    # Dataset validation
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            COUNT(prediction_correct)

        FROM incidents
        WHERE prediction_correct IS NOT NULL
        """
    )

    validation_count = (
        cursor.fetchone()[0]
    )

    cursor.execute(
        """
        SELECT
            SUM(
                CASE
                    WHEN prediction_correct = 1
                    THEN 1
                    ELSE 0
                END
            )

        FROM incidents
        """
    )

    correct_predictions = (
        cursor.fetchone()[0] or 0
    )

    validation_accuracy = 0

    if validation_count > 0:

        validation_accuracy = round(
            (
                correct_predictions /
                validation_count
            ) * 100,
            2
        )

    connection.close()

    return {

        "total_incidents":
            total_incidents,

        "attack_distribution":
            attack_distribution,

        "severity_distribution":
            severity_distribution,

        "average_risk_score":
            round(
                average_risk_score,
                2
            )
            if average_risk_score is not None
            else 0,

        "dataset_validation_count":
            validation_count,

        "dataset_validation_accuracy":
            validation_accuracy
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "Initializing database..."
    )

    initialize_database()

    print(
        f"Database: {DATABASE_PATH}"
    )

    print(
        get_dashboard_statistics()
    )