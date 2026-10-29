import { useQuery } from "@tanstack/react-query";
import { api } from "../services/api";

export const useHealth = () => useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 20_000, retry: false });
export const useModelInfo = () => useQuery({ queryKey: ["model-info"], queryFn: api.modelInfo, retry: false });
export const useSummary = () => useQuery({ queryKey: ["summary"], queryFn: api.summary, retry: false, staleTime: 60_000 });
export const useMetrics = () => useQuery({ queryKey: ["metrics"], queryFn: api.metrics, retry: false, staleTime: 60_000 });
