"""
Analizador de vectores CVSS 3.1
Este módulo proporciona una función para analizar vectores CVSS 3.1,
calcular sus scores base, temporal y ambiental, y generar una URL para 
la calculadora CVSS con los parámetros precargados."""
from urllib.parse import quote
from cvss import CVSS3

def analizar_cvss(vector: str) -> dict:
    """
    Analiza un vector CVSS 3.1, retorna los scores base, temporal y ambiental,
    y genera la URL de la calculadora con parámetros precargados.
    """
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("Este analizador solo admite vectores que comiencen con 'CVSS:3.1/'")

    try:
        cvss = CVSS3(vector)
    except Exception as e:
        raise ValueError(f"Error al analizar el vector: {e}") from e

    base_score = cvss.base_score
    temporal_score = cvss.temporal_score
    environmental_score = cvss.environmental_score

    final_score = (
        environmental_score if environmental_score is not None else
        temporal_score if temporal_score is not None else
        base_score
    )

    parametros_vector = vector.replace("CVSS:3.1/", "")
    parametros_url = quote(parametros_vector, safe=':/')

    url_calculadora = f"https://www.first.org/cvss/calculator/3.1#CVSS:3.1/{parametros_url}"

    return {
        "vector": vector,
        "base_score": round(base_score, 1),
        "temporal_score": round(temporal_score, 1) if temporal_score else None,
        "environmental_score": round(environmental_score, 1) if environmental_score else None,
        "final_score": round(final_score, 1),
        "calculadora_url": url_calculadora
    }


