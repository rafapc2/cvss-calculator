import calculator

def main():
    """
    Ejecuta test de la calculadora CVSS 3.1.
    """
    print("Iniciando calculadora CVSS 3.1...")
    # Ejemplo de uso
    vector_log4shell  = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
    resultado = calculator.analizar_cvss(vector_log4shell)

    print_results(resultado)

    
    vector_log4shell2 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L/E:P/RL:T/RC:R/CR:M/IR:L/AR:M/MAV:A/MAC:L/MPR:L/MS:U/MC:H/MI:H/MA:L"
    resultado2 = calculator.analizar_cvss(vector_log4shell2)
    print_results(resultado2)
 
    #calculator.analyze_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C")

    # Add your main logic here
def print_results(results):
    """
    Imprime los resultados de la calculadora CVSS 3.1.
    """
    print("\n---\n")
    for k, v in results.items():
        print(f"{k}: {v}")
    print("\n")


if __name__ == "__main__":
    main()
