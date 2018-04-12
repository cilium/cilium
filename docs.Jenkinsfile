pipeline {
    agent {
        label 'baremetal'
    }

    options {
        timeout(time: 10, unit: 'MINUTES')
        timestamps()
    }
    stages {
        stage('Docs') {
            steps {
                checkout scm
                sh "make test-docs"
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
