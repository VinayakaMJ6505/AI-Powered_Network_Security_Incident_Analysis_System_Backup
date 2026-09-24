import axios from "axios";


// ============================================================
// API CONFIGURATION
// ============================================================

const API_BASE_URL = "http://127.0.0.1:8000";


const api = axios.create({

    baseURL: API_BASE_URL,

    headers: {
        "Content-Type": "application/json",
    },

    timeout: 30000,

});


// ============================================================
// API ERROR HELPER
// ============================================================

export const getApiErrorMessage = (
    error,
    fallbackMessage = "An unexpected API error occurred."
) => {

    // --------------------------------------------------------
    // FastAPI HTTPException
    // --------------------------------------------------------

    if (
        error?.response?.data?.detail
    ) {

        return String(
            error.response.data.detail
        );

    }


    // --------------------------------------------------------
    // Generic API message
    // --------------------------------------------------------

    if (
        error?.response?.data?.message
    ) {

        return String(
            error.response.data.message
        );

    }


    // --------------------------------------------------------
    // Axios error message
    // --------------------------------------------------------

    if (
        error?.message
    ) {

        return error.message;

    }


    return fallbackMessage;

};


// ============================================================
// HEALTH
// ============================================================

export const checkHealth = async () => {

    const response =
        await api.get(
            "/api/health"
        );


    /*
     * Return the FastAPI JSON body.
     *
     * Example:
     *
     * {
     *     success: true,
     *     status: "healthy",
     *     message: "..."
     * }
     */

    return response.data;

};


// ============================================================
// DASHBOARD
// ============================================================

export const getDashboardStatistics =
    async () => {

        const response =
            await api.get(
                "/api/dashboard"
            );


        /*
         * Returns:
         *
         * {
         *     success: true,
         *     data: {...}
         * }
         */

        return response.data;

    };


// ============================================================
// ALL INCIDENTS
// ============================================================

export const getIncidents =
    async () => {

        const response =
            await api.get(
                "/api/incidents"
            );


        /*
         * Returns:
         *
         * {
         *     success: true,
         *     count: ...,
         *     data: [...]
         * }
         */

        return response.data;

    };


// ============================================================
// SINGLE INCIDENT
// ============================================================

export const getIncidentById =
    async (incidentId) => {

        if (
            incidentId === null ||
            incidentId === undefined ||
            incidentId === ""
        ) {

            throw new Error(
                "Incident ID is required."
            );

        }


        const response =
            await api.get(
                `/api/incidents/${incidentId}`
            );


        return response.data;

    };


// ============================================================
// MODEL INFORMATION
// ============================================================

export const getModelInfo =
    async () => {

        const response =
            await api.get(
                "/api/model"
            );


        /*
         * Returns:
         *
         * {
         *     success: true,
         *     data: {
         *         ...
         *     }
         * }
         */

        return response.data;

    };


// ============================================================
// DATASET INFORMATION
// ============================================================

export const getDatasetInfo =
    async () => {

        const response =
            await api.get(
                "/api/dataset/info"
            );


        /*
         * Returns:
         *
         * {
         *     success: true,
         *     data: {
         *         dataset_name: "...",
         *         total_records: 82332,
         *         ...
         *     }
         * }
         */

        return response.data;

    };


// ============================================================
// GET ONE DATASET RECORD
// ============================================================

export const getDatasetRecord =
    async (recordNumber) => {

        // ----------------------------------------------------
        // Validate record number before making request
        // ----------------------------------------------------

        const number =
            Number(recordNumber);


        if (
            !Number.isInteger(number) ||
            number < 1
        ) {

            throw new Error(
                "Record number must be a positive integer."
            );

        }


        // ----------------------------------------------------
        // Backend request
        // ----------------------------------------------------

        const response =
            await api.get(
                `/api/dataset/record/${number}`
            );


        /*
         * IMPORTANT:
         *
         * We return response.data here.
         *
         * Therefore AnalyzeIncident.jsx MUST use:
         *
         * const data = await getDatasetRecord(number);
         *
         * NOT:
         *
         * const response = await getDatasetRecord(number);
         * const data = response.data;
         */

        return response.data;

    };


// ============================================================
// SECURITY LOG ANALYSIS
// ============================================================

export const analyzeSecurityLog =
    async (log) => {

        if (
            !log ||
            !String(log).trim()
        ) {

            throw new Error(
                "Security log cannot be empty."
            );

        }


        const response =
            await api.post(
                "/api/logs/analyze",
                {
                    log: String(log),
                }
            );


        return response.data;

    };


// ============================================================
// COMPLETE INCIDENT ANALYSIS
// ============================================================

export const analyzeIncident = async (
    securityLog,
    networkRecord,
    validation = {}
) => {

    // --------------------------------------------------------
    // Validate security log
    // --------------------------------------------------------

    if (
        !securityLog ||
        !String(securityLog).trim()
    ) {

        throw new Error(
            "Security log cannot be empty."
        );

    }


    // --------------------------------------------------------
    // Validate network record
    // --------------------------------------------------------

    if (
        !networkRecord ||
        typeof networkRecord !== "object"
    ) {

        throw new Error(
            "A valid network record is required."
        );

    }


    // --------------------------------------------------------
    // Prepare request
    // --------------------------------------------------------

    const requestBody = {

        security_log:
            String(
                securityLog
            ),

        network_record:
            networkRecord,

        dataset_id:
            validation?.dataset_id
            ?? null,

        ground_truth_attack:
            validation?.ground_truth_attack
            ?? null,

        ground_truth_label:
            validation?.ground_truth_label
            ?? null,

    };


    // --------------------------------------------------------
    // Backend request
    // --------------------------------------------------------

    const response =
        await api.post(
            "/api/analyze",
            requestBody
        );


    /*
     * Returns:
     *
     * {
     *     success: true,
     *     message: "...",
     *     data: {
     *         incident_id: ...,
     *         incident: {...},
     *         explanation: {...},
     *         dataset_validation: {...}
     *     }
     * }
     */

    return response.data;

};


// ============================================================
// DEFAULT AXIOS INSTANCE
// ============================================================

export default api;