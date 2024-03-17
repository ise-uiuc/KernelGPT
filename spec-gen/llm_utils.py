from openai import OpenAI
from pathlib import Path
from loguru import logger
import time


api_key = (
    (Path(__file__).parent / "openai.key").read_text().strip()
)  # you need to create a file named "openai.key" and put your API key in it
client = OpenAI(api_key=api_key)

system_message = (
    "You are Syzkaller specification generator and "
    "linux kernel source code analyzer."
    "You only reply with JSON."
)


def query_gpt4(prompt: str, temperature=0.1):
    max_tokens = 4096
    failure_count = 0
    while True:
        try:
            logger.info(f"Invoke GPT-4 with max_tokens={max_tokens}")
            t_start = time.time()
            response = client.chat.completions.create(
                model="gpt-4-1106-preview",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
                temperature=temperature,
                n=1,
            )
            g_time = time.time() - t_start
            logger.info(f"GPT-4 response time: {g_time}")
            break
        except Exception as e:
            failure_count += 1
            logger.info(f"Exception: {e}")
            if "maximum context length" in str(e):
                max_tokens = max_tokens // 2
                logger.info(f"Reduce max_tokens to {max_tokens}")
            if failure_count > 20:
                logger.error("Too many failures, skip this prompt")
                break
            time.sleep(10)
    if failure_count > 20:
        return None
    return response.choices[0].message.content


def extract_code_block(text: str):
    lines = text.split("\n")
    code_block = []
    in_code_block = False
    for line in lines:
        if line.strip() in ["```", "```json"]:
            in_code_block = not in_code_block
        elif in_code_block:
            code_block.append(line)
    return "\n".join(code_block)


def query_ollm(prompt: str, temperature=0.1):
    ollm_client = OpenAI(api_key="EMPTY", base_url="http://localhost:9999/v1")
    ollm_name = "TheBloke/deepseek-coder-33B-instruct-AWQ"
    max_tokens = 4096
    failure_count = 0
    while True:
        try:
            logger.info(f"Invoke OLLM with max_tokens={max_tokens}")
            t_start = time.time()
            response = ollm_client.chat.completions.create(
                model=ollm_name,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                stop=["}\n```"],
                temperature=temperature,
                n=1,
            )
            g_time = time.time() - t_start
            logger.info(f"OLLM response time: {g_time}")
            break
        except Exception as e:
            failure_count += 1
            logger.info(f"Exception: {e}")
            if "maximum context length" in str(e):
                max_tokens = max_tokens // 2
                logger.info(f"Reduce max_tokens to {max_tokens}")
            if failure_count > 20:
                logger.error("Too many failures, skip this prompt")
                break
            time.sleep(10)
    if failure_count > 20:
        return None

    # Add the post-processing step
    answer = response.choices[0].message.content
    answer += "}\n```"
    answer = extract_code_block(answer)

    return answer
