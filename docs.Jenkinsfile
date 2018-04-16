pipeline {
    agent {
        label 'baremetal'
    }

    options {
        timeout(time: 100, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Docs') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }
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
