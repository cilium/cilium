@Library('cilium') _

pipeline {
    agent none

    environment{
        sha1="""${sh(
                returnStdout: true,
                script: 'git ls-remote https://github.com/cilium/cilium.git master | cut -f 1'
            )}"""
    }

    options {
        timeout(time: 540, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Trigger parallel baremetal K8s builds') {
            parallel {
                stage('K8s-1.14-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.14-kernel-4.9", parameters: [
                            string(name: 'sha1', value: "${sha1}")
                        ])
                    }
                }

                stage('K8s-1.15-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.15-kernel-4.9", parameters: [
                            string(name: 'sha1', value: "${sha1}")
                        ])
                    }
                }

                stage('K8s-1.16-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.16-kernel-4.9", parameters: [
                            string(name: 'sha1', value: "${sha1}")
                        ])
                    }
                }

                stage('K8s-1.17-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.17-kernel-4.9", parameters: [
                            string(name: 'sha1', value: "${sha1}")
                        ])
                    }
                }

                stage('K8s-1.18-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.18-kernel-4.9", parameters: [
                            string(name: 'sha1', value: "${sha1}")
                        ])
                    }
                }

                stage('K8s-1.19-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.19-kernel-4.9", parameters: [
                            string(name: 'sha1', value: "${sha1}")
                        ])
                    }
                }
            }
        }
    }
    post {
        success {
            Status("SUCCESS", "${env.JOB_NAME}")
        }
        failure {
            Status("FAILURE", "${env.JOB_NAME}")
        }
    }
}
