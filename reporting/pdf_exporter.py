from pathlib import Path

try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


def export_to_pdf(html_path: str, pdf_path: str) -> str:
    """
    Convert HTML report to PDF using WeasyPrint.
    Returns path to generated PDF.
    """
    if not WEASYPRINT_AVAILABLE:
        raise ImportError(
            "WeasyPrint is not installed or missing system dependencies.\n"
            "Run: sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0\n"
            "Then: pip install weasyprint==62.3"
        )

    html_path = Path(html_path)
    pdf_path  = Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Converting HTML to PDF (this takes 10-30 seconds)...")

    html = weasyprint.HTML(filename=str(html_path))
    html.write_pdf(str(pdf_path))

    size_kb = pdf_path.stat().st_size / 1024
    print(f"[+] PDF saved to: {pdf_path} ({size_kb:.1f} KB)")
    return str(pdf_path)
