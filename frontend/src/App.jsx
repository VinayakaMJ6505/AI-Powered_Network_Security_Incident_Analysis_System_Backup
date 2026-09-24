import { useState } from "react";

import Dashboard from "./pages/Dashboard";
import AnalyzeIncident from "./pages/AnalyzeIncident";

import "./App.css";


function App() {

    const [activePage, setActivePage] =
        useState("dashboard");


    return (

        <div className="app">


            {/* ==================================================
                SIDEBAR
            ================================================== */}

            <aside className="sidebar">


                {/* BRAND */}

                <div className="brand">

                    <div className="brand-icon">
                        🛡
                    </div>


                    <div className="brand-text">

                        <h2>
                            NetSecure AI
                        </h2>


                        <span>
                            Incident Analysis
                        </span>

                    </div>

                </div>


                {/* NAVIGATION TITLE */}

                <div className="sidebar-section-title">
                    MAIN
                </div>


                {/* NAVIGATION */}

                <nav className="sidebar-nav">


                    {/* DASHBOARD */}

                    <button
                        className={
                            activePage === "dashboard"
                                ? "nav-item active"
                                : "nav-item"
                        }
                        onClick={() =>
                            setActivePage("dashboard")
                        }
                    >

                        <span className="nav-icon">
                            ▦
                        </span>


                        <span>
                            Dashboard
                        </span>

                    </button>


                    {/* ANALYZE */}

                    <button
                        className={
                            activePage === "analyze"
                                ? "nav-item active"
                                : "nav-item"
                        }
                        onClick={() =>
                            setActivePage("analyze")
                        }
                    >

                        <span className="nav-icon">
                            +
                        </span>


                        <span>
                            Analyze Incident
                        </span>

                    </button>

                </nav>


                {/* SIDEBAR STATUS */}

                <div className="sidebar-bottom">

                    <div className="system-info">

                        <span className="status-dot"></span>


                        <div>

                            <strong>
                                System Online
                            </strong>


                            <small>
                                API connected
                            </small>

                        </div>

                    </div>


                    <div className="sidebar-version">
                        v1.0.0
                    </div>

                </div>

            </aside>


            {/* ==================================================
                MAIN CONTENT
            ================================================== */}

            <main className="main-content">


                {/* TOP BAR */}

                <header className="topbar">

                    <div>

                        <span className="topbar-label">
                            AI NETWORK SECURITY
                        </span>

                    </div>


                    <div className="topbar-right">

                        <span className="connection-status">

                            <span className="status-dot"></span>

                            API Connected

                        </span>

                    </div>

                </header>


                {/* CONTENT */}

                <div className="content-wrapper">


                    {activePage === "dashboard" && (

                        <Dashboard />

                    )}


                    {activePage === "analyze" && (

                        <AnalyzeIncident />

                    )}

                </div>

            </main>

        </div>
    );
}


export default App;