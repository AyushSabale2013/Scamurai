import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import type { ClassName } from "../types/api";

/** Session-memory only: nothing is written to storage and full URLs are never kept (registered domain only). */
export interface RecentItem { at: number; domain: string; className: ClassName; score: number }
interface Ctx { items: RecentItem[]; add: (i: RecentItem) => void; clear: () => void }
const RecentContext = createContext<Ctx>({ items: [], add: () => {}, clear: () => {} });

export function RecentProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<RecentItem[]>([]);
  const value = useMemo<Ctx>(() => ({
    items,
    add: (i) => setItems((p) => [i, ...p].slice(0, 8)),
    clear: () => setItems([]),
  }), [items]);
  return <RecentContext.Provider value={value}>{children}</RecentContext.Provider>;
}
export const useRecent = () => useContext(RecentContext);
