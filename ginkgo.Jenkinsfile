@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }
    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR = "${WORKSPACE}/${PROJ_PATH}/"
        MEMORY = "3072"
        ISPR = ispr()
    }

    options {
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
    }
    stages {
        stage('Checkout') {
            steps {
                sh 'env'
                BuildIfLabel('area/k8s', 'Test_projects/eloy-test')
                BuildIfLabel("area/CI", "Test_projects/eloy-test")
                sh 'rm -rf src; mkdir -p src/github.com/cilium'
                sh 'ln -s $WORKSPACE src/github.com/cilium/cilium'
                checkout scm

            }
        }
    }
    post {
        always {
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.7 vagrant destroy -f || true'
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.10 vagrant destroy -f || true'
            cleanWs()
        }
    }
}
