from cvss import CVSS3
from urllib.parse import quote

def analizar_cvss(vector: str) -> dict:
    """
    Analiza un vector CVSS 3.1, retorna los scores base, temporal y ambiental,
    y genera una URL a la calculadora online con los parámetros cargados.
    """
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("Este analizador solo admite vectores CVSS con prefijo 'CVSS:3.1/'")

    try:
        cvss = CVSS3(vector)
    except Exception as e:
        raise ValueError(f"Vector inválido: {e}")

    # Prepara los parámetros para URL (sin 'CVSS:3.1/')
    parametros_vector = vector.replace("CVSS:3.1/", "")
    parametros_url = quote(parametros_vector, safe=':/')

    url_calculadora = f"https://www.first.org/cvss/calculator/3.1#{parametros_url}"

    return {
        "vector": vector,
        "base_score": round(cvss.base_score, 1),
        "temporal_score": round(cvss.temporal_score, 1) if cvss.temporal_score else None,
        "environmental_score": round(cvss.environmental_score, 1) if cvss.environmental_score else None,
        "final_score": round(cvss.score(), 1),
        "calculadora_url": url_calculadora
    }

# Ejemplo: Log4Shell
vector_log4shell = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
resultado = analizar_cvss(vector_log4shell)

# Mostrar resultados
for clave, valor in resultado.items():
    print(f"{clave}: {valor}")
