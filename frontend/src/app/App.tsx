import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import { RecentProvider } from "../hooks/recent";
import { createAppRouter } from "./router";

const router = createAppRouter();
const client = new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false } } });

export function App() {
  return (
    <QueryClientProvider client={client}>
      <RecentProvider>
        <RouterProvider router={router} />
      </RecentProvider>
    </QueryClientProvider>
  );
}
