pipeline {
    agent any
    environment {
        STAGING_URL = "http://<VM2-IP>:4001"
        PRODUCTION_URL = "http://<VM2-IP>:4002"
        ZAP_API_KEY = "seu_api_key"
    }
    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/OWASP/NodeGoat.git'
            }
        }
        stage('SAST Analysis') {
            steps {
                script {
                    // Executa a análise SAST com Snyk
                    def result = sh(script: 'snyk test --json', returnStdout: true)
                    def json = readJSON text: result

                    // Verifica se há vulnerabilidades de risco médio ou alto
                    def mediumSeverityIssues = json.vulnerabilities.findAll { it.severity == 'medium' }
                    def highSeverityIssues = json.vulnerabilities.findAll { it.severity == 'high' }

                    if (mediumSeverityIssues.size() > 0 || highSeverityIssues.size() > 0) {
                        error "SAST Analysis failed with ${mediumSeverityIssues.size()} medium and ${highSeverityIssues.size()} high severity vulnerabilities"
                    }
                }
            }
        }
        stage('Build Staging') {
            when {
                expression {
                    // Somente executar esta etapa se a análise SAST for bem-sucedida
                    currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
            }
            steps {
                script {
                    // Derruba contêineres anteriores de staging se existirem
                    sh 'docker-compose stop web-staging mongo-staging'
                    sh 'docker-compose rm -f web-staging mongo-staging'
                    // Sobe o ambiente de staging
                    sh 'docker-compose up -d web-staging mongo-staging'
                }
            }
        }
        stage('Start OWASP ZAP') {
            when {
                expression {
                    // Somente executar esta etapa se a análise SAST for bem-sucedida
                    currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
            }
            steps {
                script {
                    // Inicia o OWASP ZAP em modo daemon
                    sh 'zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.key=${ZAP_API_KEY}'
                }
            }
        }
        stage('DAST Analysis') {
            when {
                expression {
                    // Somente executar esta etapa se a análise SAST for bem-sucedida
                    currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
            }
            steps {
                script {
                    // Aguarda o OWASP ZAP iniciar
                    sleep 10

                    // Executa o script Python do ZAP
                    def zapResult = sh(script: '''
                        python3 - <<EOF
import time
from zapv2 import ZAPv2

zap = ZAPv2(apikey='${ZAP_API_KEY}', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
target = '${STAGING_URL}'

# Start a new session
zap.core.new_session(name='Top10Scan', overwrite=True)

# Spider the target
zap.spider.scan(target)
while int(zap.spider.status()) < 100:
    time.sleep(2)

# Perform an active scan
zap.ascan.scan(target, recurse=true)
while int(zap.ascan.status()) < 100:
    time.sleep(5)

# Generate the report
with open('zap_report.html', 'w') as f:
    f.write(zap.core.htmlreport())

EOF
                    ''', returnStatus: true)
                    if (zapResult != 0) {
                        error "DAST Analysis failed. Check ZAP report for details."
                    }

                    // Verifica se o relatório ZAP contém vulnerabilidades de alto risco
                    def zapReport = readFile('zap_report.html')
                    def highRiskAlerts = zapReport.findAll { it.contains('High') }
                    if (highRiskAlerts.size() > 0) {
                        error "DAST Analysis found high risk vulnerabilities."
                    }
                }
            }
        }
        stage('Deploy to Production') {
            when {
                expression {
                    // Somente executar esta etapa se a análise SAST for bem-sucedida
                    currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
            }
            steps {
                script {
                    // Derruba contêineres anteriores de produção se existirem
                    sh 'docker-compose stop web-production mongo-production'
                    sh 'docker-compose rm -f web-production mongo-production'
                    // Sobe o ambiente de produção
                    sh 'docker-compose up -d web-production mongo-production'
                }
            }
        }
    }
    post {
        always {
            // Derruba todos os contêineres ao final do pipeline
            sh 'docker-compose down -v --remove-orphans'
            // Arquiva o relatório ZAP
            archiveArtifacts artifacts: 'zap_report.html', allowEmptyArchive: true
        }
    }
}
