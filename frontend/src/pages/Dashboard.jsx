import { useEffect, useState } from "react";

import {
    getDashboardStatistics,
    getIncidents,
} from "../services/api";


// ============================================================
// MODEL EVALUATION INFORMATION
// ============================================================

const MODEL_TEST_ACCURACY = 76.97;

const MODEL_TEST_RECORDS = 82332;


// ============================================================
// DASHBOARD
// ============================================================

function Dashboard() {

    const [statistics, setStatistics] = useState(null);

    const [incidents, setIncidents] = useState([]);

    const [loading, setLoading] = useState(true);

    const [error, setError] = useState("");


    // ========================================================
    // LOAD DASHBOARD
    // ========================================================

    const loadDashboard = async () => {

        try {

            setLoading(true);

            setError("");

            const [
                dashboardResponse,
                incidentsResponse,
            ] = await Promise.all([

                getDashboardStatistics(),

                getIncidents(),

            ]);


            setStatistics(
                dashboardResponse?.data || {}
            );


            setIncidents(
                Array.isArray(
                    incidentsResponse?.data
                )
                    ? incidentsResponse.data
                    : []
            );

        } catch (err) {

            console.error(
                "Dashboard error:",
                err
            );

            setError(
                err?.response?.data?.detail ||
                "Unable to connect to the security analysis API."
            );

        } finally {

            setLoading(false);

        }
    };


    // ========================================================
    // INITIAL LOAD
    // ========================================================

    useEffect(() => {

        loadDashboard();

    }, []);


    // ========================================================
    // LOADING
    // ========================================================

    if (loading) {

        return (

            <div className="dashboard-state">

                <div className="loading-spinner"></div>

                <p>
                    Loading security dashboard...
                </p>

            </div>

        );

    }


    // ========================================================
    // ERROR
    // ========================================================

    if (error) {

        return (

            <div className="dashboard-state error-state">

                <div className="state-icon">
                    !
                </div>

                <h2>
                    Unable to Load Dashboard
                </h2>

                <p>
                    {error}
                </p>

                <button
                    className="primary-button"
                    onClick={loadDashboard}
                >
                    Retry
                </button>

            </div>

        );

    }


    // ========================================================
    // BASIC STATISTICS
    // ========================================================

    const totalIncidents =
        Number(
            statistics?.total_incidents || 0
        );


    const averageRisk =
        Number(
            statistics?.average_risk_score || 0
        );


    const attackDistribution =
        statistics?.attack_distribution || {};


    const severityDistribution =
        statistics?.severity_distribution || {};


    const attackEntries =
        Object.entries(
            attackDistribution
        );


    const severityEntries =
        Object.entries(
            severityDistribution
        );


    // ========================================================
    // APPLICATION VALIDATION
    // ========================================================

    const validatedIncidents =
        incidents.filter(
            incident =>
                incident.prediction_correct !== null &&
                incident.prediction_correct !== undefined
        );


    const correctPredictions =
        validatedIncidents.filter(
            incident =>

                incident.prediction_correct === true ||

                Number(
                    incident.prediction_correct
                ) === 1

        ).length;


    const incorrectPredictions =
        validatedIncidents.filter(
            incident =>

                incident.prediction_correct === false ||

                Number(
                    incident.prediction_correct
                ) === 0

        ).length;


    const calculatedValidationCount =
        validatedIncidents.length;


    const calculatedValidationAccuracy =

        calculatedValidationCount > 0

            ? (
                  correctPredictions /
                  calculatedValidationCount
              ) * 100

            : 0;


    // ========================================================
    // BACKEND VALIDATION STATISTICS
    // ========================================================

    const backendValidationCount =
        Number(
            statistics?.dataset_validation_count || 0
        );


    const backendValidationAccuracy =
        Number(
            statistics?.dataset_validation_accuracy || 0
        );


    const validationCount =

        backendValidationCount > 0

            ? backendValidationCount

            : calculatedValidationCount;


    const validationAccuracy =

        backendValidationCount > 0

            ? backendValidationAccuracy

            : calculatedValidationAccuracy;


    // ========================================================
    // VALIDATION PERCENTAGES
    // ========================================================

    const correctPercentage =

        validationCount > 0

            ? (
                  correctPredictions /
                  validationCount
              ) * 100

            : 0;


    const incorrectPercentage =

        validationCount > 0

            ? (
                  incorrectPredictions /
                  validationCount
              ) * 100

            : 0;


    // ========================================================
    // MOST DETECTED ATTACK
    // ========================================================

    const mostDetectedAttack =

        attackEntries.length > 0

            ? attackEntries.reduce(
                  (
                      maximum,
                      current
                  ) =>

                      Number(current[1]) >
                      Number(maximum[1])

                          ? current
                          : maximum

              )

            : ["None", 0];


    // ========================================================
    // RENDER
    // ========================================================

    return (

        <div className="dashboard-page">

            {/* ==================================================
                PAGE HEADER
            ================================================== */}

            <div className="page-header">

                <div>

                    <div className="page-title-row">

                        <div className="shield-icon">
                            🛡
                        </div>

                        <div>

                            <h1>
                                Security Dashboard
                            </h1>

                            <p>
                                AI-powered network security
                                incident monitoring and analysis
                            </p>

                        </div>

                    </div>

                </div>


                <button
                    className="refresh-button"
                    onClick={loadDashboard}
                >
                    ↻ Refresh
                </button>

            </div>


            {/* ==================================================
                API STATUS
            ================================================== */}

            <div className="system-status">

                <span className="status-dot"></span>

                <span>
                    Security Analysis API Connected
                </span>

                <span className="status-url">
                    127.0.0.1:8000
                </span>

            </div>


            {/* ==================================================
                TOP STATISTICS
            ================================================== */}

            <div className="stats-grid">

                <div className="stat-card">

                    <div className="stat-card-top">

                        <span className="stat-label">
                            Total Incidents
                        </span>

                        <span className="stat-icon">
                            ◈
                        </span>

                    </div>

                    <div className="stat-value">
                        {totalIncidents}
                    </div>

                    <div className="stat-description">
                        Security incidents analyzed
                    </div>

                </div>


                <div className="stat-card">

                    <div className="stat-card-top">

                        <span className="stat-label">
                            Average Risk
                        </span>

                        <span className="stat-icon">
                            ◉
                        </span>

                    </div>

                    <div className="stat-value">
                        {averageRisk.toFixed(2)}
                    </div>

                    <div className="stat-description">
                        Project-defined risk score
                    </div>

                </div>


                <div className="stat-card">

                    <div className="stat-card-top">

                        <span className="stat-label">
                            Detected Attack Types
                        </span>

                        <span className="stat-icon">
                            ⚠
                        </span>

                    </div>

                    <div className="stat-value">
                        {attackEntries.length}
                    </div>

                    <div className="stat-description">
                        Classifications in incident history
                    </div>

                </div>


                <div className="stat-card">

                    <div className="stat-card-top">

                        <span className="stat-label">
                            Model Test Accuracy
                        </span>

                        <span className="stat-icon">
                            ✓
                        </span>

                    </div>

                    <div className="stat-value">
                        {MODEL_TEST_ACCURACY.toFixed(2)}%
                    </div>

                    <div className="stat-description">
                        XGBoost test-set evaluation
                    </div>

                </div>

            </div>


            {/* ==================================================
                MODEL PERFORMANCE
            ================================================== */}

            <div className="dashboard-panel model-performance-panel">

                <div className="panel-header">

                    <div>

                        <h2>
                            Model Performance
                        </h2>

                        <p>
                            Model evaluation and application-level
                            prediction validation
                        </p>

                    </div>

                    <span className="panel-icon">
                        ◉
                    </span>

                </div>


                <div className="performance-comparison-grid">

                    {/* MODEL TEST ACCURACY */}

                    <div className="performance-card model-performance-card">

                        <div className="performance-card-header">

                            <div className="performance-icon">
                                ✓
                            </div>

                            <div>

                                <h3>
                                    Model Test Accuracy
                                </h3>

                                <span>
                                    UNSW-NB15 test dataset
                                </span>

                            </div>

                        </div>


                        <div className="performance-value">
                            {MODEL_TEST_ACCURACY.toFixed(2)}%
                        </div>


                        <div className="performance-progress-track">

                            <div
                                className="performance-progress-bar"
                                style={{
                                    width:
                                        `${MODEL_TEST_ACCURACY}%`
                                }}
                            />

                        </div>


                        <p className="performance-description">

                            Final XGBoost model evaluation across{" "}

                            {MODEL_TEST_RECORDS.toLocaleString()}

                            {" "}testing records.

                        </p>


                        <div className="performance-meta">

                            <span>
                                Evaluation Dataset
                            </span>

                            <strong>
                                UNSW-NB15
                            </strong>

                        </div>


                        <div className="performance-meta">

                            <span>
                                Test Records
                            </span>

                            <strong>
                                {MODEL_TEST_RECORDS.toLocaleString()}
                            </strong>

                        </div>


                        <div className="performance-meta">

                            <span>
                                Metric Type
                            </span>

                            <strong>
                                Dataset Evaluation
                            </strong>

                        </div>

                    </div>


                    {/* APPLICATION VALIDATION */}

                    <div className="performance-card validation-performance-card">

                        <div className="performance-card-header">

                            <div className="performance-icon">
                                ◉
                            </div>

                            <div>

                                <h3>
                                    Application Validation
                                </h3>

                                <span>
                                    Stored incident history
                                </span>

                            </div>

                        </div>


                        <div className="performance-value">
                            {validationAccuracy.toFixed(2)}%
                        </div>


                        <div className="performance-progress-track">

                            <div
                                className="performance-progress-bar"
                                style={{
                                    width:
                                        `${Math.max(
                                            0,
                                            Math.min(
                                                100,
                                                validationAccuracy
                                            )
                                        )}%`
                                }}
                            />

                        </div>


                        <p className="performance-description">

                            Accuracy from incidents analyzed with
                            available UNSW-NB15 ground-truth labels.

                        </p>


                        <div className="performance-meta">

                            <span>
                                Validated Incidents
                            </span>

                            <strong>
                                {validationCount}
                            </strong>

                        </div>


                        <div className="performance-meta">

                            <span>
                                Correct Predictions
                            </span>

                            <strong>
                                {correctPredictions}
                            </strong>

                        </div>


                        <div className="performance-meta">

                            <span>
                                Incorrect Predictions
                            </span>

                            <strong>
                                {incorrectPredictions}
                            </strong>

                        </div>

                    </div>

                </div>


                {/* METRIC DISTINCTION */}

                <div className="performance-note">

                    <span className="performance-note-icon">
                        ℹ
                    </span>

                    <div>

                        <strong>
                            Metric distinction
                        </strong>

                        <p>

                            <b>
                                {MODEL_TEST_ACCURACY.toFixed(2)}%
                            </b>

                            {" "}is the XGBoost model's accuracy on the
                            UNSW-NB15 test dataset, while

                            <b>
                                {" "}
                                {validationAccuracy.toFixed(2)}%
                            </b>

                            {" "}represents the accuracy of predictions
                            currently validated against stored
                            ground-truth incidents.

                        </p>

                    </div>

                </div>

            </div>


            {/* ==================================================
                ATTACK + SEVERITY
            ================================================== */}

            <div className="analytics-grid">

                {/* ATTACK DISTRIBUTION */}

                <div className="dashboard-panel">

                    <div className="panel-header">

                        <div>

                            <h2>
                                Attack Distribution
                            </h2>

                            <p>
                                Machine-learning classifications
                            </p>

                        </div>

                        <span className="panel-icon">
                            ◈
                        </span>

                    </div>


                    <div className="distribution-list">

                        {attackEntries.length === 0 ? (

                            <div className="empty-message">
                                No attack data available.
                            </div>

                        ) : (

                            attackEntries.map(
                                ([attack, count]) => {

                                    const percentage =

                                        totalIncidents > 0

                                            ? (
                                                  Number(count) /
                                                  totalIncidents
                                              ) * 100

                                            : 0;

                                    return (

                                        <div
                                            className="distribution-item"
                                            key={attack}
                                        >

                                            <div className="distribution-info">

                                                <span>
                                                    {attack}
                                                </span>

                                                <strong>
                                                    {count}
                                                </strong>

                                            </div>


                                            <div className="progress-track">

                                                <div
                                                    className="progress-bar attack-progress"
                                                    style={{
                                                        width:
                                                            `${percentage}%`
                                                    }}
                                                />

                                            </div>

                                        </div>

                                    );

                                }
                            )

                        )}

                    </div>

                </div>


                {/* SEVERITY DISTRIBUTION */}

                <div className="dashboard-panel">

                    <div className="panel-header">

                        <div>

                            <h2>
                                Severity Distribution
                            </h2>

                            <p>
                                Project-defined risk severity
                            </p>

                        </div>

                        <span className="panel-icon">
                            ⚠
                        </span>

                    </div>


                    <div className="severity-list">

                        {severityEntries.length === 0 ? (

                            <div className="empty-message">
                                No severity data available.
                            </div>

                        ) : (

                            severityEntries.map(
                                ([severity, count]) => {

                                    const percentage =

                                        totalIncidents > 0

                                            ? (
                                                  Number(count) /
                                                  totalIncidents
                                              ) * 100

                                            : 0;

                                    return (

                                        <div
                                            className="severity-card"
                                            key={severity}
                                        >

                                            <div
                                                className={
                                                    `severity-indicator severity-${String(
                                                        severity
                                                    ).toLowerCase()}`
                                                }
                                            />

                                            <div className="severity-content">

                                                <span>
                                                    {severity}
                                                </span>

                                                <strong>
                                                    {count}
                                                </strong>

                                            </div>

                                            <div className="severity-percentage">
                                                {percentage.toFixed(0)}%
                                            </div>

                                        </div>

                                    );

                                }
                            )

                        )}

                    </div>

                </div>

            </div>


            {/* ==================================================
                RECENT SECURITY INCIDENTS
            ================================================== */}

            <div className="dashboard-panel incidents-panel">

                <div className="panel-header">

                    <div>

                        <h2>
                            Recent Security Incidents
                        </h2>

                        <p>
                            Ground truth versus XGBoost prediction
                        </p>

                    </div>

                    <span className="incident-count">
                        {incidents.length} Records
                    </span>

                </div>


                {incidents.length === 0 ? (

                    <div className="empty-incidents">

                        <div className="empty-icon">
                            ◈
                        </div>

                        <h3>
                            No incidents recorded
                        </h3>

                        <p>
                            Analyze a network security incident
                            to see it here.
                        </p>

                    </div>

                ) : (

                    <div className="table-wrapper">

                        <table className="incident-table">

                            <thead>

                                <tr>

                                    <th>ID</th>

                                    <th>Event</th>

                                    <th>Ground Truth</th>

                                    <th>Prediction</th>

                                    <th>Confidence</th>

                                    <th>Risk Score</th>

                                    <th>Validation</th>

                                    <th>Severity</th>

                                    <th>Time</th>

                                </tr>

                            </thead>


                            <tbody>

                                {incidents.map(
                                    incident => {

                                        const isValidated =

                                            incident.prediction_correct !== null &&
                                            incident.prediction_correct !== undefined;


                                        const isCorrect =

                                            incident.prediction_correct === true ||

                                            Number(
                                                incident.prediction_correct
                                            ) === 1;


                                        const validationStatus =

                                            !isValidated

                                                ? "NOT VALIDATED"

                                                : isCorrect

                                                    ? "CORRECT"

                                                    : "INCORRECT";


                                        return (

                                            <tr
                                                key={
                                                    incident.id
                                                }
                                            >

                                                <td>

                                                    <span className="incident-id">

                                                        #
                                                        {incident.id}

                                                    </span>

                                                </td>


                                                <td>

                                                    <span className="event-name">

                                                        {
                                                            incident.detected_event ||
                                                            "Unknown"
                                                        }

                                                    </span>

                                                </td>


                                                <td>

                                                    {isValidated ? (

                                                        <span className="ground-truth-badge">

                                                            {
                                                                incident.ground_truth_attack ||
                                                                "N/A"
                                                            }

                                                        </span>

                                                    ) : (

                                                        <span className="ground-truth-na">
                                                            N/A
                                                        </span>

                                                    )}

                                                </td>


                                                <td>

                                                    <span className="attack-badge">

                                                        {
                                                            incident.predicted_attack ||
                                                            "Unknown"
                                                        }

                                                    </span>

                                                </td>


                                                <td>

                                                    {(
                                                        Number(
                                                            incident.confidence ||
                                                            0
                                                        ) * 100
                                                    ).toFixed(2)}

                                                    %

                                                </td>


                                                <td>

                                                    <strong>

                                                        {Number(
                                                            incident.risk_score ||
                                                            0
                                                        ).toFixed(2)}

                                                    </strong>

                                                </td>


                                                <td>

                                                    <span
                                                        className={
                                                            `validation-badge ${
                                                                isValidated

                                                                    ? isCorrect

                                                                        ? "validation-correct"

                                                                        : "validation-incorrect"

                                                                    : "validation-not-validated"
                                                            }`
                                                        }
                                                    >

                                                        {validationStatus}

                                                    </span>

                                                </td>


                                                <td>

                                                    <span
                                                        className={
                                                            `severity-badge severity-badge-${String(
                                                                incident.risk_severity ||
                                                                "UNKNOWN"
                                                            ).toLowerCase()}`
                                                        }
                                                    >

                                                        {
                                                            incident.risk_severity ||
                                                            "UNKNOWN"
                                                        }

                                                    </span>

                                                </td>


                                                <td>

                                                    {formatDate(
                                                        incident.created_at
                                                    )}

                                                </td>

                                            </tr>

                                        );

                                    }
                                )}

                            </tbody>

                        </table>

                    </div>

                )}

            </div>

        </div>

    );
}


// ============================================================
// DATE FORMATTER
// ============================================================

function formatDate(
    dateString
) {

    if (!dateString) {

        return "N/A";
    }

    const date =
        new Date(dateString);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return dateString;
    }

    return date.toLocaleString();
}


export default Dashboard;