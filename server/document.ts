import { PDFParse } from "pdf-parse";
import mammoth from "mammoth";

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const TEXT_EXTENSIONS = new Set([".txt", ".md", ".csv", ".json", ".html", ".htm", ".xml", ".log"]);

export class DocumentInputError extends Error {}

function extensionOf(fileName: string) {
  const lower = fileName.toLowerCase();
  const index = lower.lastIndexOf(".");
  return index >= 0 ? lower.slice(index) : "";
}

export async function extractDocumentText(fileName: string, mimeType: string, bytes: Buffer) {
  if (bytes.length === 0) throw new DocumentInputError("The uploaded file is empty.");
  if (bytes.length > MAX_FILE_BYTES) throw new DocumentInputError("Files must be 10 MB or smaller.");

  const extension = extensionOf(fileName);
  const isPlainText = mimeType.startsWith("text/") || TEXT_EXTENSIONS.has(extension);
  if (isPlainText) {
    return bytes.toString("utf8").replace(/\u0000/g, "").trim();
  }

  if (mimeType === "application/pdf" || extension === ".pdf") {
    const parser = new PDFParse({ data: bytes });
    try {
      const result = await parser.getText();
      const text = result.text.replace(/\u0000/g, "").trim();
      if (!text) {
        throw new DocumentInputError("This PDF has no selectable text. Image-only PDFs need OCR support.");
      }
      return text;
    } finally {
      await parser.destroy();
    }
  }

  if (
    mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
    extension === ".docx"
  ) {
    const result = await mammoth.extractRawText({ buffer: bytes });
    const text = result.value.replace(/\u0000/g, "").trim();
    if (!text) throw new DocumentInputError("This DOCX does not contain readable text.");
    return text;
  }

  throw new DocumentInputError("Unsupported file type. Use PDF, DOCX, TXT, MD, CSV, JSON, HTML, or XML.");
}
