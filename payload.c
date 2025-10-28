#include <stdio.h>

// Marcador para garantir que a função seja exportada corretamente em uma DLL (Windows)
#if defined(_WIN32)
    #define DllExport __declspec(dllexport)
#else
    #define DllExport
#endif

/*
    Função de engodo (decoy) que realiza um cálculo intensivo.
    Malwares podem usar técnicas como esta para:
    1. Dificultar a análise, fazendo o analista perder tempo em código inútil.
    2. Tentar evadir sandboxes que limitam o tempo de execução.
    3. Alterar o estado do sistema (CPU, temperatura) para detectar ambientes de análise.
*/
DllExport void run_decoy_calculation() {
    printf("[+] PAYLOAD C: Iniciando cálculo intensivo de engodo...\n");
    long long i;
    double result = 0.0;

    // Loop simples para consumir ciclos de CPU
    for (i = 0; i < 2000000000; i++) {
        result += (double)i * 3.1415926535 / 2.7182818284;
    }

    printf("[+] PAYLOAD C: Cálculo de engodo concluído. Resultado (inútil): %f\n", result);
}

// Função principal (main) para permitir testes independentes do código C.
// Este trecho não é executado quando o arquivo é usado como uma DLL.
int main() {
    run_decoy_calculation();
    return 0;
}
