import sys
from importlib.metadata import version
from pathlib import Path

tool_version = version("PySecrypt")

def show_version():
    # Custom ASCII Art for the project name
    ascii_art = r"""
 ____           ____                                          __      
/\  _`\        /\  _`\                                       /\ \__   
\ \ \L\ \__  __\ \,\L\_\     __    ___   _ __   __  __  _____\ \ ,_\  
 \ \ ,__/\ \/\ \\/_\__ \   /'__`\ /'___\/\`'__\/\ \/\ \/\ '__`\ \ \/  
  \ \ \/\ \ \_\ \ /\ \L\ \/\  __//\ \__/\ \ \/ \ \ \_\ \ \ \L\ \ \ \_ 
   \ \_\ \/`____ \\ `\____\ \____\ \____\\ \_\  \/`____ \ \ ,__/\ \__\
    \/_/  `/___/> \\/_____/\/____/\/____/ \/_/   `/___/> \ \ \/  \/__/
             /\___/                                 /\___/\ \_\       
             \/__/                                  \/__/  \/_/       
    """
    readme_path = Path(__file__).resolve().parent.parent.parent / "README.md"
    if not readme_path.exists():
        readme_path = "README.md file not found. Please check your installation."
        
    # Project details
    version_info = f"""
{ascii_art}
          PySecrypt CLI Tool v{tool_version}

  Developed By    : George Zimvragos
  Institution     : University of East London
  Department      : Computer Science
  Project Type    : Thesis Project
  Version Purpose : Educational Demonstration
  Summary         : A CLI tool for demonstrating encryption techniques.


  Notes:
  * This tool is part of an academic thesis project and is intended for educational purposes.
  * Avoid using for large files as it loads the entire file into memory.
  * Future versions will implement stream processing. 

  Documentation:
  * For detailed usage, please refer to the instructions in the README.md file:
  """
    
    print(f"{version_info}")
    sys.exit(0)
