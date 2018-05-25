@Library('cilium') _
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
                Status("PENDING", "${env.JOB_NAME}")
                checkout scm
                sh "make test-docs"
            }
        }
    }
    post {
        always {
            cleanWs()
        }
        success {
            Status("SUCCESS", "${env.JOB_NAME}")
        }
        failure {
            Status("FAILURE", "${env.JOB_NAME}")
        }
    }
}
