#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include "hash_utils.h"

#define MAX_WORKERS 16
#define RESULT_FILE "password_found.txt"

/**
 * @brief Calcula o espaço de busca total de senhas.
 *
 * @param charset_len O tamanho do conjunto de caracteres.
 * @param password_len O comprimento da senha.
 * @return O número total de combinações possíveis.
 */
long long calculate_search_space(int charset_len, int password_len) {
    long long total = 1;
    for (int i = 0; i < password_len; i++) total *= charset_len;
    return total;
}

/**
 * @brief Converte um índice numérico em uma string de senha.
 *
 * Esta função é crucial para o coordinator dividir o trabalho de forma
 * equitativa e lexicográfica.
 *
 * @param index O índice numérico da senha no espaço de busca.
 * @param charset O conjunto de caracteres a ser usado.
 * @param charset_len O tamanho do conjunto de caracteres.
 * @param password_len O comprimento da senha.
 * @param output O buffer onde a senha convertida será armazenada.
 */
void index_to_password(long long index, const char *charset, int charset_len,
                       int password_len, char *output) {
    for (int i = password_len - 1; i >= 0; i--) {
        output[i] = charset[index % charset_len];
        index /= charset_len;
    }
    output[password_len] = '\0';
}

int main(int argc, char *argv[]) {
    // TODO 1: Validar argumentos de linha de comando
    // - número de argumentos, comprimento da senha, número de workers

    if(argc != 5){
        printf("Ocorreu um erro porque o comando deve ter 5 argumentos. Exemplo de uso: ./coordinator <hash> <tamanho> <charset> <workers>\n");
        return 1;
    }

    const char *target_hash = argv[1];
    int password_len = atoi(argv[2]);
    const char *charset = argv[3];
    int num_workers = atoi(argv[4]);
    int charset_len = strlen(charset);

    if(password_len < 1 || password_len > 10){
        printf("erro, a senha deve ter entre 1 e 10 caracteres.\n");
        return 1;
    }
    if(num_workers < 1 || num_workers > MAX_WORKERS){
        printf("tem que ter mais de 1 e menos de %d workers\n", MAX_WORKERS);
        return 1;
    }
    if (charset_len == 0) {
        fprintf(stderr, "Erro: O charset não pode ser vazio.\n");
        return 1;
    }

    printf("=== Mini-Projeto 1: Quebra de Senhas Paralelo ===\n");
    printf("Hash MD5 alvo: %s\n", target_hash);
    printf("Tamanho da senha: %d\n", password_len);
    printf("Charset: %s (tamanho: %d)\n", charset, charset_len);
    printf("Número de workers: %d\n", num_workers);

    // TODO 2: Calcular espaço de busca total
    long long total_space = calculate_search_space(charset_len, password_len);
    printf("Espaço de busca total: %lld combinações\n\n", total_space);

    // TODO 3: Remover o arquivo de resultado anterior
    unlink(RESULT_FILE);

    time_t start_time = time(NULL);

    // TODO 4: Dividir o trabalho e iniciar os workers
    long long passwords_per_worker = total_space / num_workers;
    long long remaining = total_space % num_workers;
    long long start_index = 0;
    pid_t workers[MAX_WORKERS];
    
    printf("Iniciando workers...\n");

    for (int i = 0; i < num_workers; i++) {
        long long piece_size = passwords_per_worker;
        if (i < remaining) piece_size++;
        
        char start_pass[password_len + 1], end_pass[password_len + 1];
        
        index_to_password(start_index, charset, charset_len, password_len, start_pass);
        index_to_password(start_index + piece_size - 1, charset, charset_len, password_len, end_pass);

        // Criar worker
        pid_t pid = fork();
        if(pid < 0){
            perror("Erro no fork");
            exit(1);
        }

        if(pid == 0){
            // processo filho executa worker
            char worker_id_str[10];
            char password_len_str[10];
            
            sprintf(worker_id_str, "%d", i); 
            sprintf(password_len_str, "%d", password_len);
            
            execl("./worker", "./worker",
                  target_hash,
                  start_pass,
                  end_pass,
                  charset,
                  password_len_str,
                  worker_id_str,
                  NULL);
            perror("Erro no execl");
            exit(1);
        } else {
            // processo pai armazena PID
            workers[i] = pid;
        }

        start_index += piece_size;
    }

    printf("\nTodos os workers foram iniciados. Aguardando conclusão...\n");

    // TODO 5: Esperar todos os workers
    for(int i = 0; i < num_workers; i++){
        int status;
        pid_t wpid = waitpid(workers[i], &status, 0);
        if(WIFEXITED(status)){
            printf("[Coordinator] Worker %d terminou com código %d\n", i, WEXITSTATUS(status));
        } else {
            printf("[Coordinator] Worker %d terminou de forma anormal.\n", i);
        }
    }

    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);

    printf("\n=== Resultado ===\n");

    // TODO 6: Ler o arquivo de resultado e exibir a senha encontrada
    FILE *fp = fopen(RESULT_FILE, "r");
    if(fp){
        char line[256];
        while(fgets(line, sizeof(line), fp)){
            int worker_id;
            char found_password[100];
            if(sscanf(line, "%d:%s", &worker_id, found_password) == 2){
                printf("[RESULTADO] Worker %d: %s\n", worker_id, found_password);
            }
        }
        fclose(fp);
    } else {
        printf("Nenhum worker encontrou a senha. \nCertifique-se de que o hash e os outros parâmetros estão corretos.\n");
    }

    printf("\nTempo total: %.2f segundos\n", elapsed_time);

    return 0;
}
    } else {
        printf("Nenhum worker encontrou a senha. \nCertifique-se de que o hash e os outros parÃ¢metros estÃ£o corretos.\n");
    }

    printf("\nTempo total: %.2f segundos\n", elapsed_time);

    return 0;
}
