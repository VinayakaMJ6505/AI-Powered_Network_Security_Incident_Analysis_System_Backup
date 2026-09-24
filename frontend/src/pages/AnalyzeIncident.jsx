import { useEffect, useState } from "react";

import {
    analyzeIncident,
    getDatasetInfo,
    getDatasetRecord,
    getModelInfo
} from "../services/api";


// ============================================================
// MODEL FEATURES
// ============================================================

const MODEL_FEATURES = [
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
    "state"
];


// ============================================================
// COMPONENT
// ============================================================

function AnalyzeIncident() {

    const [datasetInfo, setDatasetInfo] = useState(null);
    const [recordNumber, setRecordNumber] = useState(1);
    const [datasetRecord, setDatasetRecord] = useState(null);
    const [datasetLoading, setDatasetLoading] = useState(true);

    const [networkRecord, setNetworkRecord] = useState({});
    const [securityLog, setSecurityLog] = useState("");
    const [groundTruth, setGroundTruth] = useState(null);

    const [result, setResult] = useState(null);
    const [modelInfo, setModelInfo] = useState(null);

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");


    // ========================================================
    // INITIAL LOAD
    // ========================================================

    useEffect(() => {
        loadInitialData();
    }, []);


    // ========================================================
    // INITIAL DATA
    // ========================================================

    const loadInitialData = async () => {

        try {

            setDatasetLoading(true);
            setError("");

            const [
                datasetResponse,
                modelResponse
            ] = await Promise.all([
                getDatasetInfo(),
                getModelInfo()
            ]);

            setDatasetInfo(
                datasetResponse?.data ?? null
            );

            setModelInfo(
                modelResponse?.data ?? null
            );

            await loadDatasetRecord(1);

        } catch (err) {

            console.error(
                "Initial data loading error:",
                err
            );

            const detail =
                err?.response?.data?.detail;

            setError(
                detail ||
                err?.message ||
                "Unable to load dataset information."
            );

        } finally {

            setDatasetLoading(false);

        }
    };


    // ========================================================
    // LOAD DATASET RECORD
    // ========================================================

    const loadDatasetRecord = async (
        requestedRecordNumber
    ) => {

        try {

            setDatasetLoading(true);
            setError("");
            setResult(null);

            const data =
                await getDatasetRecord(
                    requestedRecordNumber
                );

            if (!data) {

                throw new Error(
                    "Dataset record response was empty."
                );

            }

            if (data.success === false) {

                throw new Error(
                    data.message ||
                    "Unable to load dataset record."
                );

            }

            if (!data.network_record) {

                throw new Error(
                    "Dataset record does not contain network features."
                );

            }

            setDatasetRecord(data);

            setNetworkRecord(
                data.network_record
            );

            setGroundTruth({

                id:
                    data.dataset_id ??
                    null,

                attack_cat:
                    data.ground_truth_attack ??
                    null,

                label:
                    data.ground_truth_label ??
                    null

            });

            setSecurityLog(
                formatSecurityLog(
                 data.security_log || ""
                )
            );

            setRecordNumber(
                data.record_number ??
                requestedRecordNumber
            );

            console.log(
                "Dataset record loaded successfully:",
                data
            );

        } catch (err) {

            console.error(
                "Dataset record loading error:",
                err
            );

            const detail =
                err?.response?.data?.detail;

            setError(
                detail ||
                err?.message ||
                "Unable to load dataset record."
            );

            setDatasetRecord(null);
            setNetworkRecord({});
            setGroundTruth(null);
            setSecurityLog("");

        } finally {

            setDatasetLoading(false);

        }
    };


    // ========================================================
    // RECORD NUMBER CHANGE
    // ========================================================

    const handleRecordNumberChange = (
        event
    ) => {

        setRecordNumber(
            event.target.value
        );

    };


    // ========================================================
    // LOAD RECORD
    // ========================================================

    const handleLoadRecord = async () => {

        const requestedRecord =
            Number(recordNumber);

        const totalRecords =
            Number(
                datasetInfo?.total_records || 0
            );

        if (
            !Number.isInteger(
                requestedRecord
            )
        ) {

            setError(
                "Please enter a valid record number."
            );

            return;
        }

        if (
            requestedRecord < 1
        ) {

            setError(
                "Record number must be at least 1."
            );

            return;
        }

        if (
            totalRecords > 0 &&
            requestedRecord > totalRecords
        ) {

            setError(
                `Record number must be between 1 and ${totalRecords.toLocaleString()}.`
            );

            return;
        }

        await loadDatasetRecord(
            requestedRecord
        );
    };


    // ========================================================
    // ENTER KEY
    // ========================================================

    const handleRecordKeyDown = (
        event
    ) => {

        if (
            event.key === "Enter"
        ) {

            event.preventDefault();

            handleLoadRecord();
        }
    };


    // ========================================================
    // ANALYZE INCIDENT
    // ========================================================

    const handleAnalyze = async (
        event
    ) => {

        event.preventDefault();

        setError("");
        setResult(null);

        if (
            !securityLog.trim()
        ) {

            setError(
                "Please provide a security log."
            );

            return;
        }

        if (
            !networkRecord ||
            Object.keys(
                networkRecord
            ).length !==
            MODEL_FEATURES.length
        ) {

            setError(
                "Please load a valid UNSW-NB15 dataset record first."
            );

            return;
        }

        const missingFeatures =
            MODEL_FEATURES.filter(
                feature =>
                    !Object.prototype.hasOwnProperty.call(
                        networkRecord,
                        feature
                    )
            );

        if (
            missingFeatures.length > 0
        ) {

            setError(
                "Missing model features: " +
                missingFeatures.join(", ")
            );

            return;
        }

        try {

            setLoading(true);

            const response =
                await analyzeIncident(
                    securityLog,
                    networkRecord,
                    {
                        dataset_id:
                            groundTruth?.id ??
                            null,

                        ground_truth_attack:
                            groundTruth?.attack_cat ??
                            null,

                        ground_truth_label:
                            groundTruth?.label ??
                            null
                    }
                );

            setResult(response);

            console.log(
                "Incident analysis result:",
                response
            );

        } catch (err) {

            console.error(
                "Incident analysis error:",
                err
            );

            const detail =
                err?.response?.data?.detail;

            setError(
                detail ||
                err?.message ||
                "Unable to analyze the security incident."
            );

        } finally {

            setLoading(false);

        }
    };


    // ========================================================
    // RESET
    // ========================================================

    const handleReset = () => {

        setResult(null);
        setError("");

        if (datasetRecord) {

            setSecurityLog(
                 formatSecurityLog(
                datasetRecord.security_log ||
                 ""
                )
            );

            setNetworkRecord(
                datasetRecord.network_record ||
                {}
            );

            setGroundTruth({

                id:
                    datasetRecord.dataset_id ??
                    null,

                attack_cat:
                    datasetRecord.ground_truth_attack ??
                    null,

                label:
                    datasetRecord.ground_truth_label ??
                    null

            });
        }
    };


    // ========================================================
    // RESULT OBJECTS
    // ========================================================

    const incident =
        result?.data?.incident;

    const explanation =
        result?.data?.explanation;

    const validation =
        result?.data?.dataset_validation;

    const probabilities =
        incident
            ?.ml_prediction
            ?.probabilities
        ?? {};


    // ========================================================
    // RENDER
    // ========================================================

    return (

        <div className="analysis-page">

            {/* ==================================================
                HEADER
            ================================================== */}

            <div className="page-header">

                <div>

                    <h1>
                        Analyze Security Incident
                    </h1>

                    <p>
                        Analyze a network event using NLP,
                        machine learning and project-defined
                        risk assessment.
                    </p>

                </div>

            </div>


            {/* ==================================================
                DATASET VALIDATION
            ================================================== */}

            <div className="analysis-card">

                <div className="card-header">

                    <div>

                        <h2>
                            UNSW-NB15 Dataset Validation
                        </h2>

                        <p>
                            Load any testing-dataset record
                            by entering its record number.
                        </p>

                    </div>

                </div>


                <div className="dataset-toolbar">

                    <div className="dataset-status">

                        <label>
                            Testing Dataset
                        </label>

                        <div>

                            {datasetLoading

                                ? "Loading..."

                                : datasetInfo

                                    ? `${datasetInfo.dataset_name || "UNSW-NB15"} — ${Number(
                                        datasetInfo.total_records || 0
                                    ).toLocaleString()} records available`

                                    : "Dataset unavailable"

                            }

                        </div>

                    </div>


                    <div className="dataset-selector">

                        <label htmlFor="record-number">
                            Record Number
                        </label>

                        <div className="record-input-group">

                            <input
                                id="record-number"
                                type="number"
                                min="1"
                                max={
                                    datasetInfo?.total_records
                                    || undefined
                                }
                                value={recordNumber}
                                onChange={
                                    handleRecordNumberChange
                                }
                                onKeyDown={
                                    handleRecordKeyDown
                                }
                                disabled={
                                    datasetLoading
                                }
                                placeholder="Enter record number"
                            />

                            <button
                                type="button"
                                className="load-record-button"
                                onClick={
                                    handleLoadRecord
                                }
                                disabled={
                                    datasetLoading ||
                                    !datasetInfo
                                }
                            >
                                {datasetLoading
                                    ? "Loading..."
                                    : "Load Record"
                                }
                            </button>

                        </div>

                        <small>

                            Enter a record number from{" "}

                            <strong>
                                1
                            </strong>

                            {" "}to{" "}

                            <strong>
                                {Number(
                                    datasetInfo?.total_records
                                    || 0
                                ).toLocaleString()}
                            </strong>

                        </small>

                    </div>

                </div>


                {error && (

                    <div className="error-message">
                        {error}
                    </div>

                )}

            </div>


            {/* ==================================================
                GROUND TRUTH
            ================================================== */}

            {groundTruth && (

                <div className="analysis-card">

                    <div className="card-header">

                        <div>

                            <h2>
                                Dataset Ground Truth
                            </h2>

                            <p>
                                Actual label associated with
                                the selected UNSW-NB15 record.
                            </p>

                        </div>

                    </div>


                    <div className="ground-truth-panel">

                        <div className="feature-field">

                            <span>
                                Record Number
                            </span>

                            <strong>
                                {recordNumber}
                            </strong>

                        </div>


                        <div className="feature-field">

                            <span>
                                Dataset ID
                            </span>

                            <strong>
                                {groundTruth.id ?? "N/A"}
                            </strong>

                        </div>


                        <div className="feature-field">

                            <span>
                                Ground Truth Attack
                            </span>

                            <strong>
                                {
                                    groundTruth.attack_cat ||
                                    "N/A"
                                }
                            </strong>

                        </div>


                        <div className="feature-field">

                            <span>
                                Ground Truth Label
                            </span>

                            <strong>
                                {
                                    groundTruth.label ??
                                    "N/A"
                                }
                            </strong>

                        </div>

                    </div>

                </div>

            )}


            {/* ==================================================
                SECURITY LOG
            ================================================== */}

            <div className="analysis-card">

                <div className="card-header">

                    <div>

                        <h2>
                            Security Log
                        </h2>

                        <p>
                            Generated from the selected
                            network-flow record.
                        </p>

                    </div>

                </div>


                <textarea
                    className="security-log-textarea"
                    value={securityLog}
                    onChange={
                        event =>
                            setSecurityLog(
                                event.target.value
                            )
                    }
                    placeholder={
                        "Enter a security event or log message..."
                    }
                    rows={10}
                />

            </div>


            {/* ==================================================
                NETWORK RECORD
            ================================================== */}

            {Object.keys(
                networkRecord
            ).length > 0 && (

                <div className="analysis-card">

                    <div className="card-header">

                        <div>

                            <h2>
                                Network Record
                            </h2>

                            <p>
                                Exactly 42 features used by
                                the trained XGBoost model.
                            </p>

                        </div>

                    </div>


                    <div className="feature-grid">

                        {MODEL_FEATURES.map(
                            feature => (

                                <div
                                    className="feature-field"
                                    key={feature}
                                >

                                    <span>
                                        {
                                            formatFeatureName(
                                                feature
                                            )
                                        }
                                    </span>

                                    <strong>
                                        {
                                            formatFeatureValue(
                                                networkRecord[
                                                    feature
                                                ]
                                            )
                                        }
                                    </strong>

                                </div>

                            )
                        )}

                    </div>

                </div>

            )}


            {/* ==================================================
                MODEL INFORMATION
            ================================================== */}

            {modelInfo && (

                <div className="analysis-card">

                    <div className="card-header">

                        <div>

                            <h2>
                                Model Information
                            </h2>

                            <p>
                                Information retrieved from
                                the backend model package.
                            </p>

                        </div>

                    </div>


                    <div className="ground-truth-panel">

                        <div className="feature-field">

                            <span>
                                Model
                            </span>

                            <strong>
                                {
                                    modelInfo.model_type ||
                                    "XGBClassifier"
                                }
                            </strong>

                        </div>


                        <div className="feature-field">

                            <span>
                                Classes
                            </span>

                            <strong>
                                {
                                    modelInfo.class_count ??
                                    modelInfo.num_classes ??
                                    (
                                        Array.isArray(
                                            modelInfo.classes
                                        )
                                            ? modelInfo.classes.length
                                            : 10
                                    )
                                }
                            </strong>

                        </div>


                        <div className="feature-field">

                            <span>
                                Raw Features
                            </span>

                            <strong>
                                {
                                    modelInfo.raw_feature_count ??
                                    modelInfo.feature_count ??
                                    42
                                }
                            </strong>

                        </div>


                        <div className="feature-field">

                            <span>
                                Processed Features
                            </span>

                            <strong>
                                {
                                    modelInfo.processed_feature_count ??
                                    modelInfo.processed_features ??
                                    194
                                }
                            </strong>

                        </div>

                    </div>

                </div>

            )}


            {/* ==================================================
                ACTION BUTTONS
            ================================================== */}

            <div className="analysis-actions">

                <button
                    type="button"
                    className="analyze-button"
                    onClick={handleAnalyze}
                    disabled={
                        loading ||
                        datasetLoading ||
                        Object.keys(
                            networkRecord
                        ).length !==
                        MODEL_FEATURES.length
                    }
                >

                    {loading
                        ? "Analyzing..."
                        : "Analyze Incident"
                    }

                </button>


                <button
                    type="button"
                    className="clear-button"
                    onClick={handleReset}
                    disabled={loading}
                >
                    Clear / Reset
                </button>

            </div>


            {/* ==================================================
                RESULTS
            ================================================== */}

            {result && (

                <>

                    {/* ==================================================
                        PREDICTION VALIDATION
                    ================================================== */}

                    <div className="analysis-card">

                        <div className="card-header">

                            <div>

                                <h2>
                                    Prediction Validation
                                </h2>

                                <p>
                                    Comparison between the
                                    dataset ground truth and
                                    the XGBoost prediction.
                                </p>

                            </div>

                        </div>


                        <div className="ground-truth-panel">

                            <div className="feature-field">

                                <span>
                                    Ground Truth
                                </span>

                                <strong>
                                    {
                                        validation
                                            ?.ground_truth_attack ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    AI Prediction
                                </span>

                                <strong>
                                    {
                                        validation
                                            ?.predicted_attack ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Ground Truth Label
                                </span>

                                <strong>
                                    {
                                        validation
                                            ?.ground_truth_label ??
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Validation
                                </span>

                                <strong
                                    className={
                                        validation
                                            ?.prediction_correct === true
                                            ? "validation-correct-text"
                                            : validation
                                                ?.prediction_correct === false
                                                ? "validation-incorrect-text"
                                                : "validation-not-validated-text"
                                    }
                                >

                                    {
                                        validation
                                            ?.prediction_correct === true

                                            ? "CORRECT"

                                            : validation
                                                ?.prediction_correct === false

                                                ? "INCORRECT"

                                                : "NOT VALIDATED"
                                    }

                                </strong>

                            </div>

                        </div>

                    </div>


                    {/* ==================================================
                        AI / ML PREDICTION
                    ================================================== */}

                    <div className="analysis-card">

                        <div className="card-header">

                            <div>

                                <h2>
                                    AI / ML Prediction
                                </h2>

                                <p>
                                    XGBoost network security
                                    classification result.
                                </p>

                            </div>

                        </div>


                        <div className="ground-truth-panel">

                            <div className="feature-field">

                                <span>
                                    Predicted Attack
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.ml_prediction
                                            ?.predicted_attack ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Confidence
                                </span>

                                <strong>
                                    {
                                        formatPercentage(
                                            incident
                                                ?.ml_prediction
                                                ?.confidence
                                        )
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Risk Score
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.risk_analysis
                                            ?.risk_score ??
                                        "N/A"
                                    }
                                    /100
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Severity
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.risk_analysis
                                            ?.severity ||
                                        "N/A"
                                    }
                                </strong>

                            </div>

                        </div>

                    </div>


                    {/* ==================================================
                        PROBABILITIES
                    ================================================== */}

                    <div className="analysis-card">

                        <div className="card-header">

                            <div>

                                <h2>
                                    Prediction Probabilities
                                </h2>

                                <p>
                                    Probability distribution
                                    across all attack classes.
                                </p>

                            </div>

                        </div>


                        <div className="probability-list">

                            {Object.entries(
                                probabilities
                            )
                                .sort(
                                    (
                                        [, a],
                                        [, b]
                                    ) =>
                                        Number(b) -
                                        Number(a)
                                )
                                .map(
                                    (
                                        [
                                            attack,
                                            probability
                                        ]
                                    ) => {

                                        const percentage =
                                            Number(
                                                probability
                                            ) * 100;

                                        return (

                                            <div
                                                className="probability-row"
                                                key={attack}
                                            >

                                                <div className="probability-header">

                                                    <span>
                                                        {attack}
                                                    </span>

                                                    <strong>
                                                        {
                                                            formatPercentage(
                                                                probability
                                                            )
                                                        }
                                                    </strong>

                                                </div>


                                                <div className="probability-bar">

                                                    <div
                                                        className="probability-fill"
                                                        style={{
                                                            width:
                                                                `${Math.max(
                                                                    0,
                                                                    Math.min(
                                                                        100,
                                                                        percentage
                                                                    )
                                                                )}%`
                                                        }}
                                                    />

                                                </div>

                                            </div>

                                        );

                                    }
                                )
                            }

                        </div>

                    </div>


                    {/* ==================================================
                        NLP ANALYSIS
                    ================================================== */}

                    <div className="analysis-card">

                        <div className="card-header">

                            <div>

                                <h2>
                                    NLP Analysis
                                </h2>

                                <p>
                                    Information extracted from
                                    the security log.
                                </p>

                            </div>

                        </div>


                        <div className="ground-truth-panel">

                            <div className="feature-field">

                                <span>
                                    Event
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.nlp_analysis
                                            ?.event ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Source IP
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.nlp_analysis
                                            ?.source_ip ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Destination IP
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.nlp_analysis
                                            ?.destination_ip ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Port
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.nlp_analysis
                                            ?.port ??
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Protocol
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.nlp_analysis
                                            ?.protocol ||
                                        "N/A"
                                    }
                                </strong>

                            </div>


                            <div className="feature-field">

                                <span>
                                    Service
                                </span>

                                <strong>
                                    {
                                        incident
                                            ?.nlp_analysis
                                            ?.service ??
                                        "N/A"
                                    }
                                </strong>

                            </div>

                        </div>

                    </div>


                    {/* ==================================================
                        INCIDENT EXPLANATION
                    ================================================== */}

                    <div className="analysis-card">

                        <div className="card-header">

                            <div>

                                <h2>
                                    Incident Explanation
                                </h2>

                            </div>

                        </div>


                        <div className="explanation-content">

                            <h3>
                                Summary
                            </h3>

                            <p>
                                {
                                    explanation
                                        ?.incident_summary ||
                                    "N/A"
                                }
                            </p>


                            <h3>
                                Technical Explanation
                            </h3>

                            <p>
                                {
                                    explanation
                                        ?.technical_explanation ||
                                    "N/A"
                                }
                            </p>


                            <h3>
                                Recommended Actions
                            </h3>

                            <ul>

                                {(
                                    explanation
                                        ?.recommended_actions ||
                                    []
                                ).map(
                                    (
                                        action,
                                        index
                                    ) => (

                                        <li
                                            key={index}
                                        >
                                            {action}
                                        </li>

                                    )
                                )}

                            </ul>

                        </div>

                    </div>


                    {/* ==================================================
                        DATABASE
                    ================================================== */}

                    <div className="analysis-card">

                        <div className="card-header">

                            <div>

                                <h2>
                                    Database
                                </h2>

                                <p>
                                    Incident storage status.
                                </p>

                            </div>

                        </div>


                        <div className="saved-incident">

                            <span>
                                Saved Incident ID
                            </span>

                            <strong>
                                {
                                    result
                                        ?.data
                                        ?.incident_id ??
                                    "Not saved"
                                }
                            </strong>

                        </div>

                    </div>

                </>

            )}

        </div>

    );
}


// ============================================================
// FORMAT FEATURE NAME
// ============================================================

function formatFeatureName(
    feature
) {

    return feature
        .replaceAll(
            "_",
            " "
        )
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );
}

// ============================================================
// FORMAT SECURITY LOG
// ============================================================

function formatSecurityLog(log) {

    if (!log) {
        return "";
    }

    return String(log)
        .replace(/\s*\|\s*/g, "\n| ")
        .replace(/\n{2,}/g, "\n")
        .trim();
}


// ============================================================
// FORMAT FEATURE VALUE
// ============================================================

function formatFeatureValue(
    value
) {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return "N/A";
    }

    if (
        typeof value === "number"
    ) {

        if (
            Number.isInteger(value)
        ) {

            return value.toLocaleString();
        }

        return value.toFixed(6);
    }

    return String(value);
}


// ============================================================
// FORMAT PERCENTAGE
// ============================================================

function formatPercentage(
    value
) {

    if (
        value === null ||
        value === undefined ||
        Number.isNaN(
            Number(value)
        )
    ) {

        return "N/A";
    }

    return (
        Number(value) * 100
    ).toFixed(2) + "%";
}


export default AnalyzeIncident;