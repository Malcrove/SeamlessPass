import os
import base64
import re

from colorama import Style,Fore

class Helper:

    @staticmethod
    def maybe_read_file(input_str : str):
        if os.path.isfile(input_str):
            with open(input_str, 'rb') as file:
                return file.read()

        return input_str.encode('utf-8')


    @staticmethod
    def is_base64(data: bytes):
        # not strict base64 validation which may lead to false positives but it's acceptable for the current use
        return re.match(rb'^[\sA-Za-z0-9+/=]+$', data) is not None


    @staticmethod
    def maybe_base64_decode(data : bytes):
        try:
            if Helper.is_base64(data):
                data = base64.b64decode(data)

            #return base64.b64decode(data) if Helper.is_base64(data) else data
        except (base64.binascii.Error, UnicodeDecodeError):
            # If it's not valid base64 or not valid utf-8, return the original content
            # return data
            pass

        return data


    @staticmethod
    def maybe_add_color(data, color, show_colors=True):
        if show_colors:
          return f'{color}{data}{Style.RESET_ALL}'
        else:
          return data

    def colorize_args(args: dict, show_colors = True, arg_color=Fore.GREEN, value_color=Fore.LIGHTBLACK_EX):
        output = []
        for key,value in args.items():
            output.append(Helper.maybe_add_color(key, arg_color, show_colors))
            output.append(Helper.maybe_add_color(value, value_color, show_colors))
        return ' '.join(output)

    @staticmethod
    def pretty_print(d: dict, colored=True, indent: int = 0, padding: int = 40, print: callable = print) -> None:
        if isinstance(d, dict):
            for key, value in d.items():
                if isinstance(key, str) or isinstance(key,int):
                    key = Helper.maybe_add_color(key, Fore.GREEN, colored)

                if isinstance(value, str) or isinstance(value, int):
                    print(("  " * indent + str(key)).ljust(padding, " ") + ": %s" % value)
                elif isinstance(value, dict):
                    print("  " * indent + str(key))
                    pretty_print(value, indent=indent + 1, print=print)
                elif isinstance(value, list):
                    if len(value) > 0 and isinstance(value[0], dict):
                        print("  " * indent + str(key))
                        for v in value:
                            pretty_print(v, indent=indent + 1, print=print)
                    else:
                        print(
                            ("  " * indent + str(key)).ljust(padding, " ")
                            + ": %s"
                            % (
                                ("\n" + " " * padding + "  ").join(
                                    map(lambda x: str(x), value)
                                )
                            )
                        )
                elif isinstance(value, tuple):
                    print("  " * indent + str(key))
                    for v in value:
                        pretty_print(v, indent=indent + 1, print=print)
                elif value is None:
                    continue
                else:
                    # Shouldn't end up here
                    raise NotImplementedError("Not implemented: %s" % type(value))
        else:
            # Shouldn't end up here
            raise NotImplementedError("Not implemented: %s" % type(d))