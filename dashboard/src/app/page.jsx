import DashboardClient from "@/components/DashboardClient";
import {envBool, envInt} from "@/lib/env";

export const dynamic = "force-dynamic";

export default function DashboardPage() {
  return (
    <DashboardClient
      initialRefreshMs={envInt("DASHBOARD_REFRESH_MS", 4000, 500, 60000)}
      secretsRedacted={envBool("DASHBOARD_REDACT_SECRETS", true)}
    />
  );
}
