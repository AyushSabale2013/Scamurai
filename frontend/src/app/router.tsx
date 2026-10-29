import { createBrowserRouter } from "react-router-dom";
import { AppShell } from "../components/layout/AppShell";
import { AboutPage } from "../pages/About";
import { AnalyzerPage } from "../pages/Analyzer";
import { BatchPage } from "../pages/Batch";
import { DatasetPage } from "../pages/Dataset";
import { ModelLabPage } from "../pages/ModelLab";
import { OverviewPage } from "../pages/Overview";

export const routes = [
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "analyzer", element: <AnalyzerPage /> },
      { path: "batch", element: <BatchPage /> },
      { path: "model-lab", element: <ModelLabPage /> },
      { path: "dataset", element: <DatasetPage /> },
      { path: "about", element: <AboutPage /> },
      { path: "*", element: <div className="py-20 text-center text-fog-300">Page not found.</div> },
    ],
  },
];

export const createAppRouter = () => createBrowserRouter(routes);
