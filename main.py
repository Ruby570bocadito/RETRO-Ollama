#!/usr/bin/env python3
"""
PTAI - Pentesting AI Tool
Main entry point with enhanced CLI options
"""

import sys
import os
import argparse
import logging

# Fix for Windows Unicode encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('ptai.log', encoding='utf-8')
        ]
    )

def print_banner():
    """Print startup banner"""
    from src.cli_app import print_banner as pb
    pb()

def run_interactive(nobanner=False):
    """Run in interactive mode"""
    if not nobanner:
        print_banner()
    from src.cli_app import app
    app()

def run_command(cmd: str, model: str = None, host: str = None):
    """Run a single command and exit"""
    from src.cli_app import app
    sys.argv = ['ptai', '--cmd', cmd]
    if model:
        sys.argv.extend(['--model', model])
    if host:
        sys.argv.extend(['--host', host])
    app()

def run_agent_task(task: str, model: str = None):
    """Run autonomous agent task"""
    from src.ai.agent import auto_agent
    from src.cli_app import get_client
    
    print_banner()
    print(f"[*] Running agent task: {task}")
    
    # Get client
    ollama = get_client()
    
    # Check connection
    if not ollama.check_connection():
        print("[!] Cannot connect to backend")
        sys.exit(1)
    
    # Get model
    model_name = model or "llama3.2"
    if not model:
        models = ollama.list_models()
        if models:
            model_name = models[0].get('name', 'llama3.2')
    
    # Run agent
    result = auto_agent.process(task, ollama, model_name)
    print(result)
    
    # Print summary
    print("\n[*] Agent Summary:")
    print(auto_agent.generate_summary())

def run_workflow(workflow: str, target: str, model: str = None):
    """Run a predefined workflow"""
    from src.ai.agent import auto_agent
    from src.cli_app import get_client
    
    print_banner()
    print(f"[*] Running workflow: {workflow} on {target}")
    
    # Get client
    ollama = get_client()
    
    if not ollama.check_connection():
        print("[!] Cannot connect to backend")
        sys.exit(1)
    
    # Get model
    model_name = model or "llama3.2"
    if not model:
        models = ollama.list_models()
        if models:
            model_name = models[0].get('name', 'llama3.2')
    
    # Run workflow
    result = auto_agent.run_workflow(workflow, target, ollama, model_name)
    print(result)
    
    # Print summary
    print("\n[*] Agent Summary:")
    print(auto_agent.generate_summary())

def list_workflows():
    """List available workflows"""
    from src.ai.agent import AgentWorkflow
    
    print("[*] Available workflows:\n")
    
    for name, wf in AgentWorkflow.WORKFLOWS.items():
        print(f"  {name}")
        print(f"    Description: {wf['description']}")
        print(f"    Steps: {len(wf['steps'])}")
        for i, step in enumerate(wf['steps'], 1):
            print(f"      {i}. {step['description']}")
        print()

def list_modes():
    """List available modes"""
    from src.modes import list_modes
    
    print("[*] Available modes:\n")
    
    modes = list_modes()
    for mode_id, mode_info in modes.items():
        icon = mode_info.get('icon', '')
        print(f"  {mode_id}: {icon} {mode_info['name']}")
        print(f"    {mode_info['description']}")
        print()

def show_status():
    """Show agent status"""
    from src.ai.agent import auto_agent
    
    status = auto_agent.get_status()
    
    print("[*] Agent Status:\n")
    print(f"  State: {status['state']}")
    print(f"  Targets scanned: {status['memory']['targets_scanned']}")
    print(f"  Vulnerabilities found: {status['memory']['vulnerabilities_found']}")
    print(f"  Recent findings: {status['memory']['recent_findings']}")
    print(f"\n  Workflows: {', '.join(status['available_workflows'])}")
    print(f"  Tools: {len(status['available_tools'])}")
    
    if status.get('tool_stats'):
        print("\n  Tool Statistics:")
        for tool, stats in status['tool_stats'].items():
            if stats['usage'] > 0:
                print(f"    {tool}: {stats['usage']} uses, {stats['success_rate']:.1%} success")

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description='PTAI - Pentesting AI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ptai                          # Start interactive mode
  ptai --cmd "nmap localhost"   # Run command
  ptai --agent "scan 192.168.1.1"  # Run agent task
  ptai --workflow recon target.com  # Run workflow
  ptai --list-modes             # List modes
  ptai --status                # Show agent status
        """
    )
    
    parser.add_argument('--cmd', '-c', help='Run a command and exit')
    parser.add_argument('--model', '-m', help='Specify model to use')
    parser.add_argument('--host', '-H', help='Specify host (ollama://host:port)')
    parser.add_argument('--backend', '-b', choices=['ollama', 'lmstudio', 'llamacpp'], 
                       default='ollama', help='Backend to use')
    
    # Agent options
    parser.add_argument('--agent', '-a', help='Run agent task')
    parser.add_argument('--workflow', '-w', nargs=2, metavar=('WORKFLOW', 'TARGET'),
                       help='Run workflow (recon, vuln_assess, web_assess, full_pentest)')
    
    # Info options
    parser.add_argument('--list-modes', action='store_true', help='List available modes')
    parser.add_argument('--list-workflows', action='store_true', help='List available workflows')
    parser.add_argument('--status', '-s', action='store_true', help='Show agent status')
    parser.add_argument('--reset', action='store_true', help='Reset agent memory')
    
    # Other options
    parser.add_argument('--list', '-l', action='store_true', help='List available models')
    parser.add_argument('--nobanner', '-n', action='store_true', help='Hide banner')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Handle commands
    if args.list_modes:
        list_modes()
        return
    
    if args.list_workflows:
        list_workflows()
        return
    
    if args.status:
        show_status()
        return
    
    if args.reset:
        from src.ai.agent import auto_agent
        print(auto_agent.reset_memory())
        return
    
    if args.list:
        if not args.nobanner:
            print_banner()
        from src.cli_app import app
        sys.argv = ['ptai', '--list']
        app()
        return
    
    if args.workflow:
        workflow, target = args.workflow
        run_workflow(workflow, target, args.model)
        return
    
    if args.agent:
        run_agent_task(args.agent, args.model)
        return
    
    if args.cmd:
        run_command(args.cmd, args.model, args.host)
        return
    
    # Default: interactive mode
    run_interactive(args.nobanner)

if __name__ == "__main__":
    main()
