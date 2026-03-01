import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scanner";
import type { ScanRequest, ScanResponse } from "@/lib/types";

const MAX_FILE_SIZE = 512 * 1024; // 512 KB per file
const MAX_FILES = 10;

export async function POST(request: NextRequest): Promise<NextResponse> {
  let body: unknown;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json<ScanResponse>(
      { success: false, error: "Invalid JSON body" },
      { status: 400 }
    );
  }

  if (
    !body ||
    typeof body !== "object" ||
    !Array.isArray((body as ScanRequest).files)
  ) {
    return NextResponse.json<ScanResponse>(
      {
        success: false,
        error: 'Request must have a "files" array',
      },
      { status: 400 }
    );
  }

  const scanRequest = body as ScanRequest;

  if (scanRequest.files.length === 0) {
    return NextResponse.json<ScanResponse>(
      { success: false, error: "No files provided" },
      { status: 400 }
    );
  }

  if (scanRequest.files.length > MAX_FILES) {
    return NextResponse.json<ScanResponse>(
      { success: false, error: `Maximum ${MAX_FILES} files allowed per scan` },
      { status: 400 }
    );
  }

  for (const file of scanRequest.files) {
    if (!file.name || typeof file.name !== "string") {
      return NextResponse.json<ScanResponse>(
        { success: false, error: "Each file must have a name" },
        { status: 400 }
      );
    }
    if (!file.content || typeof file.content !== "string") {
      return NextResponse.json<ScanResponse>(
        { success: false, error: `File "${file.name}" has no content` },
        { status: 400 }
      );
    }
    if (file.content.length > MAX_FILE_SIZE) {
      return NextResponse.json<ScanResponse>(
        {
          success: false,
          error: `File "${file.name}" exceeds maximum size of 512KB`,
        },
        { status: 400 }
      );
    }
  }

  try {
    const result = runScan(scanRequest);
    return NextResponse.json<ScanResponse>({ success: true, result });
  } catch (err) {
    console.error("Scanner error:", err);
    return NextResponse.json<ScanResponse>(
      { success: false, error: "Internal scanner error" },
      { status: 500 }
    );
  }
}

export async function GET(): Promise<NextResponse> {
  return NextResponse.json({
    name: "ClawGuard scan API",
    version: "1.0.0",
    usage: "POST /api/scan with { files: [{ name, content }] }",
  });
}
