pipeline {
    agent any
    environment {
        STAGING_URL = "http://localhost:4001"
        PRODUCTION_URL = "http://localhost:4002"
        ZAP_API_KEY = "superseguro"
    }

    stages {

         stage('Checkout') {
            steps {
                git 'https://github.com/cybersecurityplus/NodeGoat_DevSec'
            }

      }
             

            stage('Docker UP') {
            steps {
                script{
                    sh 'docker-compose up -d web-staging mongo-staging'
                }
        }
            }
   
    }
}
