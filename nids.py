import click
from src.analytic_engine import AnalyticEngine

@click.command()
@click.option('-s','--source', required=True, help='Path to PCAP file or interface name e.g. eth0')
@click.option('-nf','--normal-pcap', help='Path to clear PCAP file - useful for training ML model')
@click.option('-mf','--malicious-pcap', help='Path to malicious PCAP file - useful for training ML model')
@click.option('-o','--output', help='Path to output report file')
@click.option('-ml','--ml-model', help='Show ML model visualization and save it to file', is_flag=True)
@click.option('-cm','--confusion-matrix', help='Show confusion matrix and save it to file', is_flag=True)
@click.option('-tpie','--threats-pie', help='Show threats pie chart and save it to file', is_flag=True)
@click.option('-tmap','--threats-map', help='Save threat map to file', is_flag=True)
@click.option('-p','--print-report', help='Print report', is_flag=True)
@click.option('-a','--all', help='Show all visualizations', is_flag=True)
@click.option('-l','--live', help='Live mode', is_flag=True)
def cli(source, normal_pcap, malicious_pcap, output, ml_model, confusion_matrix, threats_pie, threats_map, all, print_report, live):

    if live:
        print("[*] Interception started...")
        engine = AnalyticEngine(input_stream=source,ml_malicious_stream=malicious_pcap, ml_normal_stream=normal_pcap, is_live=True)
    else:
        engine = AnalyticEngine(input_stream=source,ml_malicious_stream=malicious_pcap, ml_normal_stream=normal_pcap, is_live=False)
    if output:
        engine.report.path = output
    if ml_model or all:
        print("[*] Generating ML model visualization...")
        engine.report.visualize_ml_tree()
        print("[+] ML model visualization saved to ml_tree.png")
    if confusion_matrix or all:
        print("[*] Generating confusion matrix...")
        engine.report.visualize_conf_matrix()
        print("[+] Confusion matrix saved to confusion_matrix.png")
    if threats_pie or all:
        print("[*] Generating threats pie chart...")
        engine.report.visualize_threats()
        print("[+] Threats pie chart saved to threats_pie.png")
    if threats_map or all:
        print("[*] Generating threat map...")
        engine.report.visualize_threat_map()
        print("[+] Threat map saved to threat_map.html")
    if print_report:
        print(engine.report.to_json())
    print("[*] Saving report...")
    engine.report.save_report_to_json()
    print("[+] Report saved to", engine.report.path)



if __name__ == "__main__":
    cli()
