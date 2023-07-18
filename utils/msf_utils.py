class MsfUtils:
    _priority_keywords = ['meterpreter']
    _default_selection_order = ['windows/meterpreter/reverse_tcp', 'java/meterpreter/reverse_tcp',
                                'php/meterpreter/reverse_tcp', 'php/meterpreter_reverse_tcp', 'ruby/shell_reverse_tcp',
                                'cmd/unix/interact', 'cmd/unix/reverse', 'cmd/unix/reverse_perl',
                                'cmd/unix/reverse_netcat_gaping', 'windows/meterpreter/reverse_nonx_tcp',
                                'windows/meterpreter/reverse_ord_tcp', 'windows/shell/reverse_tcp',
                                'generic/shell_reverse_tcp']

    @staticmethod
    def get_default_payload(compatible_payloads: list[str]) -> str:
        for payload_name in compatible_payloads:
            if any(keyword in payload_name for keyword in MsfUtils._priority_keywords):
                return payload_name
        for payload_name in MsfUtils._default_selection_order:
            if payload_name in compatible_payloads:
                return payload_name
        return compatible_payloads[0]
