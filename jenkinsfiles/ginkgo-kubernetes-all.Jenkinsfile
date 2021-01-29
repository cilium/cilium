@Library('cilium') _

pipeline {
    agent none

    parameters {
        string(defaultValue: 'origin/master', name: 'GIT_BRANCH')
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
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}"),
                            string(name: 'sha1', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.15-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.15-kernel-4.9", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}"),
                            string(name: 'sha1', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.16-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.16-kernel-4.9", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}"),
                            string(name: 'sha1', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.17-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.17-kernel-4.9", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}"),
                            string(name: 'sha1', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.18-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.18-kernel-4.9", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}"),
                            string(name: 'sha1', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.19-kernel-4.9') {
                    steps {
                        build(job: "Cilium-PR-K8s-1.19-kernel-4.9", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}"),
                            string(name: 'sha1', value: "${GIT_BRANCH}")
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
