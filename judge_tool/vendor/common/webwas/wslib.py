# VENDOR-EDIT(a): Django imports + parseAnalysisResult 제거.
# 원본 wslib.py에서 get_remove_line (stdlib-only 순수함수) 만 추출.
# parseAnalysisResult는 Django ORM 의존이므로 벤더에서 제거 — 어댑터가 사용하지 않음.

def get_remove_line(text, prefix):
    lines = text.split('\n')  # Using UNIX line separator
    filtered_lines = [line for line in lines if not line.strip().startswith(prefix)]
    return '\n'.join(filtered_lines)
