import subprocess


def run(request):
    command = request.args.get("command")
    subprocess.run(command, shell=True)
