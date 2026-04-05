import os
import tempfile

import pygal
from fpdf import FPDF

from src.tp1.utils.config import logger


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "IDS/IPS Report - Network Analysis"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self._graph_path = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += str(self.array)
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(26, 35, 126)
        pdf.cell(0, 12, self.title, new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)

        # Summary
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(0, 0, 0)
        for line in self.summary.split("\n"):
            pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Graph
        if self._graph_path and os.path.exists(self._graph_path):
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(26, 35, 126)
            pdf.cell(0, 8, "Protocol Chart", new_x="LMARGIN", new_y="NEXT")
            pdf.image(self._graph_path, x=15, w=180)
            pdf.ln(4)

        # Table
        if self.array:
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(26, 35, 126)
            pdf.cell(0, 8, "Protocol Table", new_x="LMARGIN", new_y="NEXT")

            # Header row
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(26, 35, 126)
            pdf.set_text_color(255, 255, 255)
            for header, width in [("Protocol", 75), ("Packets", 40), ("Status", 65)]:
                pdf.cell(width, 8, header, border=1, align="C", fill=True)
            pdf.ln()

            # Data rows
            pdf.set_font("Helvetica", "", 10)
            for i, (proto, count, status) in enumerate(self.array):
                pdf.set_fill_color(232, 234, 246) if i % 2 == 0 else pdf.set_fill_color(255, 255, 255)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(75, 7, proto, border=1, fill=True)
                pdf.cell(40, 7, count, border=1, fill=True, align="C")
                if status == "Suspicious":
                    pdf.set_text_color(180, 0, 0)
                pdf.cell(65, 7, status, border=1, fill=True, align="C")
                pdf.set_text_color(0, 0, 0)
                pdf.ln()
            pdf.ln(4)

        # Alerts section
        alerts = self.capture.alerts
        if alerts:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(180, 0, 0)
            pdf.cell(0, 8, f"Security Alerts ({len(alerts)} detected)", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            for alert in alerts:
                pdf.set_text_color(180, 0, 0)
                pdf.cell(0, 6, f"[{alert['type']}] {alert['detail']}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 6, f"  Protocol : {alert['protocol']}", new_x="LMARGIN", new_y="NEXT")
                pdf.cell(0, 6, f"  Source IP : {alert['src_ip']}", new_x="LMARGIN", new_y="NEXT")
                pdf.cell(0, 6, f"  Source MAC: {alert['src_mac']}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
        else:
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(0, 140, 0)
            pdf.cell(0, 8, "No threats detected - all traffic looks legitimate.", new_x="LMARGIN", new_y="NEXT", align="C")

        pdf.output(filename)
        logger.info(f"Report saved: {filename}")
        print(f"\nReport generated: {filename}")

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            stats = self.capture.protocols
            if not stats:
                return

            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            sorted_stats = sorted(stats.items(), key=lambda x: -x[1])
            labels = [p for p, _ in sorted_stats]
            values = [n for _, n in sorted_stats]

            fig, ax = plt.subplots(figsize=(10, 5))
            ax.bar(labels, values, color="#1a237e")
            ax.set_title("Captured network protocols")
            ax.set_xlabel("Protocol")
            ax.set_ylabel("Packet count")
            for i, v in enumerate(values):
                ax.text(i, v + 0.5, str(v), ha="center", fontsize=9)
            plt.tight_layout()

            png_path = os.path.join(tempfile.gettempdir(), "ids_graph.png")
            plt.savefig(png_path, dpi=150)
            plt.close(fig)

            self._graph_path = png_path
            self.graph = png_path

        elif param == "array":
            # Build rows: protocol, packet count, legitimacy status
            stats = self.capture.protocols
            alerts = self.capture.alerts
            suspicious_protocols = {a["protocol"] for a in alerts}

            self.array = [
                (proto, str(count), "Suspicious" if proto in suspicious_protocols else "Legitimate")
                for proto, count in sorted(stats.items(), key=lambda x: -x[1])
            ]