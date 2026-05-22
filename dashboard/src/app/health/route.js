import {NextResponse} from "next/server";
import {queryOne} from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  try {
    await queryOne("SELECT 1 AS ok");
    return NextResponse.json({status: "ok"});
  } catch (error) {
    return NextResponse.json(
      {status: "error", message: error.message},
      {status: 503}
    );
  }
}
