import {NextResponse} from "next/server";
import {envBool} from "@/lib/env";
import {getSnapshot} from "@/lib/telemetry";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  try {
    const snapshot = await getSnapshot();
    return NextResponse.json({
      status: "ok",
      generated_at: new Date().toISOString(),
      redacted: envBool("DASHBOARD_REDACT_SECRETS", true),
      ...snapshot
    });
  } catch (error) {
    return NextResponse.json(
      {
        status: "error",
        generated_at: new Date().toISOString(),
        message: error.message
      },
      {status: 503}
    );
  }
}
