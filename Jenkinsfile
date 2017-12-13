pipeline {
    agent any
    options {
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
    }
    stages {
        stage ('Tests') {
            environment {
                MEMORY = '4096'
                RUN_TEST_SUITE = '1'
            }
            steps {
     		           
                parallel(
                    "Print Environment": { sh 'env' },
                    "Runtime Tests": {
                         sh 'echo foobar'
                    },
                    failFast: true
                )
            }
        }
    }
    post {
        always {
            sh 'echo baz'
        }
    }
}




