import argparse

from colorama import Fore, Style

from .helper import Helper

class ColoredHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
       

   
    def _format_usage(self, usage, actions, groups, prefix):
        """Format the usage string with different colors for arguments and values."""
        if prefix is None:
            prefix = 'Usage: '
        
        # Start with prefix
        usage_text = Helper.maybe_add_color(prefix, Fore.YELLOW)
        usage_text += self._prog
        usage_text += ' '
        
        # Iterate over actions to colorize them
        action_usages = []
        for action in actions:
            if action.option_strings:
                # Optional arguments
                action_usage = action.option_strings[0]
                if action.nargs != 0:
                    metavar = self._metavar_formatter(action, action.dest)(1)
                    action_usage += f" {Helper.maybe_add_color(metavar[0], Fore.LIGHTBLACK_EX)}"

                if not action.required:
                    action_usage = f'[{action_usage}]'
                action_usages.append(action_usage)

            else:
                # Positional arguments
                metavar = self._metavar_formatter(action, action.dest)(1)
                action_usage = Helper.maybe_add_color(metavar[0], Fore.LIGHTBLACK_EX)
                if not action.required:
                    action_usage = f'[{action_usage}]'
                action_usages.append(action_usage)
        
        # Join the parts together
        usage_text += ' '.join(action_usages)
        return usage_text + '\n'

    def _format_action_invocation(self, action):
        """Format the invocation of the action with individual colors for each part."""
        if not action.option_strings:
            # Positional arguments
            metavar = self._metavar_formatter(action, action.dest)(1)[0]
            return Helper.maybe_add_color(metavar, Fore.LIGHTBLACK_EX)
        else:
            # Optional arguments
            parts = []
            parts.append('/'.join(action.option_strings))
            
            if action.nargs != 0:
                metavar = self._metavar_formatter(action, action.dest)(1)
                parts.append(Helper.maybe_add_color(metavar[0], Fore.LIGHTBLACK_EX))

            return ' '.join(parts)

    def start_section(self, heading):
        """Start a new section with a colored heading."""
        heading_text = Helper.maybe_add_color(heading, Fore.YELLOW)
        super().start_section(heading_text)
