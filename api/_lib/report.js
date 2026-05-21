const PDFDocument = require("pdfkit");

function severityColor(severity) {
  switch (severity) {
    case "critical": return "#b91c1c";
    case "high": return "#b45309";
    case "medium": return "#b7791f";
    case "low": return "#15803d";
    default: return "#475569";
  }
}

function renderPdf(result) {
  return new Promise((resolve) => {
    const doc = new PDFDocument({ size: "LETTER", margin: 48 });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));

    doc.fontSize(20).fillColor("#0f766e").text("VibeShield Security Report", { align: "left" });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor("#475569").text(`Scan ID: ${result.id}`);
    doc.text(`Target: ${result.target}`);
    if (result.ref) doc.text(`Ref: ${result.ref}`);
    doc.text(`Score: ${result.score} / 100`);
    doc.text(`Findings: ${result.findings.length} (${result.activeFindingsCount} active, ${result.suppressedFindingsCount} suppressed)`);
    doc.text(`Files scanned: ${result.filesScanned}`);
    doc.text(`Generated: ${new Date().toISOString()}`);
    doc.moveDown(0.6);

    doc.fontSize(13).fillColor("#0f172a").text("Severity breakdown");
    doc.moveDown(0.2);
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of result.findings.filter((finding) => !finding.suppressed)) {
      sevCounts[finding.severity] = (sevCounts[finding.severity] || 0) + 1;
    }
    for (const severity of ["critical", "high", "medium", "low"]) {
      doc.fontSize(10).fillColor(severityColor(severity)).text(`${severity.toUpperCase()}: ${sevCounts[severity] || 0}`, { continued: false });
    }
    doc.moveDown(0.5);
    doc.fillColor("#0f172a");

    doc.fontSize(13).text("Findings");
    doc.moveDown(0.3);
    const active = result.findings.filter((finding) => !finding.suppressed);
    if (!active.length) {
      doc.fontSize(10).fillColor("#15803d").text("No active findings. ");
    }
    for (const finding of active.slice(0, 80)) {
      if (doc.y > 720) doc.addPage();
      doc.fontSize(11).fillColor(severityColor(finding.severity)).text(`[${finding.severity.toUpperCase()}] ${finding.title}`);
      doc.fontSize(9).fillColor("#475569").text(`Rule: ${finding.rule}    Category: ${finding.category}    Confidence: ${finding.confidence}`);
      if (finding.file) doc.text(`Location: ${finding.file}${finding.line ? `:${finding.line}` : ""}`);
      doc.fontSize(9).fillColor("#0f172a").text(`Evidence: ${finding.evidence}`, { width: 480 });
      doc.fontSize(9).fillColor("#1f2937").text(`Fix: ${finding.fix}`, { width: 480 });
      if (Array.isArray(finding.references) && finding.references.length) {
        doc.fontSize(8).fillColor("#0f766e").text(`References: ${finding.references.join(", ")}`, { width: 480 });
      }
      doc.moveDown(0.4);
    }

    if (result.suppressedFindingsCount) {
      doc.addPage();
      doc.fontSize(13).fillColor("#0f172a").text("Suppressed findings");
      for (const finding of result.findings.filter((finding) => finding.suppressed).slice(0, 40)) {
        doc.fontSize(10).fillColor("#475569").text(`- ${finding.title} (${finding.rule}) — reason: ${finding.suppression_reason || "n/a"}`);
      }
    }

    doc.end();
  });
}

module.exports = { renderPdf };
