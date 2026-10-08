import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { FirstRun } from "./FirstRun";
import "./styles.css";
import "../public/approved-workflow.css";
import "../public/ui-theme.css";
import "../public/visual-refresh.css";
import "./dashboard-responsive.css";
import { watchRelease } from '../public/live-sync.mjs';

watchRelease();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter basename={(window as any).panelBase || '/'}>
      <FirstRun><App /></FirstRun>
    </BrowserRouter>
  </React.StrictMode>
);
