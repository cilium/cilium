pipeline {
    agent any
    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
    }

    options {
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                sh 'env'
            }
        }
    }
}
