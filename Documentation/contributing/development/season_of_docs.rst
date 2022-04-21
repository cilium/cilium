.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


.. _season_of_docs:

Google Season of Docs 2022
==========================

Cilium has been accepted into the 2022 Google Season of Docs to improve the documentation experience for our users and contributors.
Below is our project ideas, if you have any questions, please reach out to gsod@cilium.io. Technical writers can apply until April 27th
in this `form`_.

Reorganize Cilium Features and Getting Started
----------------------------------------------

About Our Organization
~~~~~~~~~~~~~~~~~~~~~~

Cilium (current version 1.11, first released in 2017) is an Apache 2.0-licensed project for providing, 
securing, and observing network connectivity between container workloads - cloud native, and built around 
the revolutionary Linux Kernel technology eBPF. Our users adopt Cilium to solve their cloud networking, 
observability, and security issues at scale including running some of the largest Kubernetes clusters in the world. 
Cilium has a large community of contributors from over 50 countries around the world. Multiple companies 
have staff paid to work on Cilium too. Cilium is an incubating project in the Cloud Native Computing Foundation 
and is the networking data plane for Google Kubernetes Engine and Anthos.

About the Problem
~~~~~~~~~~~~~~~~~

Cloud native networking and security are complex topics that even long time practitioners struggle to master.
Cilium documentation has grown organically over time and the project has mainly been used by advanced cloud native users. 
The documentation lacks the structure that new, and even existing, users can rely on to quickly find the information they need. 
In addition, users sometimes struggle to discover all of the features and functionality of Cilium because the documentation 
does not make them easily discoverable. Finally, new users often have questions about how to troubleshoot setting up their network.

Improving the structure of the documentation will help new users adopt Cilium and reduce the support load on the community.

Project Scope
~~~~~~~~~~~~~

The project will:

#. Audit the existing document structure and inventory existing documentation
#. Using the inventory as a guide, determine existing documentation and gaps for the top three use cases (Networking, Observability and Security)
#. Restructure the existing documentation to surface Cilium's capabilities more prominently and determine documentation gaps of existing functionality or missing links to existing talks or presentations
#. Simplify the “Getting Started” section by moving advanced and detailed config guides out to more appropriate sections
#. Work with the release team to restructure the documentation and create a process for keeping the documentation up to date going forward

Work that is out of scope:

#. Writing tutorials or reference documentation

The writer will be working closely with Liz Rice, Bill Mulligan, and other Cilium maintainers. 
We estimate the project will take five months to complete.

Measuring Success
~~~~~~~~~~~~~~~~~

Cilium currently receives issues covered in the documentation in both the Slack and through Github issues. It also receives few new 
contributors to the documentation. We believe that this restructuring will result in fewer questions and issues already covered in 
the documentation and more contributors to the documentation since they will know where to add it.

We will track three metrics (number of questions covered in documentation in Slack, number of questions covered in documentation 
in Github issues, and number of pull requests from new contributors) monthly after the documentation is published.

We would consider the project successful if, after publication of the new documentation each of the following happens:

- The number of Slack questions covered in the documentation decreases by 10%
- The number of Github issues covered in the documentation decreases by 20%
- The number of pull requests from new contributors increases by 15%

Timeline
~~~~~~~~

The project itself will take approximately six months to complete. Once the tech writer is hired, we'll spend a month on 
tech writer orientation, then move onto the audit and inventory, and spend the last three months focusing on restructuring the documentation.

+------------------+---------------------------------------------------+
| Dates            | Action Items                                      |
+==================+===================================================+
| May              | Orientation                                       | 
+------------------+---------------------------------------------------+
| June - July      | Audit existing documentation and create inventory | 
+------------------+---------------------------------------------------+
| August - October | Restructure documentation                         | 
+------------------+---------------------------------------------------+

Project Budget
~~~~~~~~~~~~~~

+----------------------------------------------------------------------------------+--------------+------------------+
| Budget Item                                                                      | Amount       | Running Total    | 
+==================================================================================+==============+==================+
| Technical writer audit, inventory, restructure, test, and publish documentation  | 9,000.00     | 9,000.00         | 
+----------------------------------------------------------------------------------+--------------+------------------+
| Project Swag                                                                     | 150.00       | 9,150.00         |  
+----------------------------------------------------------------------------------+--------------+------------------+
| Total                                                                            |              | 9,150.00         |
+----------------------------------------------------------------------------------+--------------+------------------+

This budget would allow us to hire a writer part time for $1,500 per month for six months.

Additional Information
~~~~~~~~~~~~~~~~~~~~~~

Cilium participated in the Google Summer of Code in 2021. Our three students successfully completed their project 
before the summer's end. One of them presented it afterward at a national conference and another continues to contribute regularly to Cilium.

This experience highlighted the importance of regular status reports/meetings between mentors and mentees. 
We also gained experience establishing realistic timelines for people with diverse backgrounds. 
Finally, this experience highlighted the need for better documentation and led us to apply for Season of Docs.

.. _form: https://forms.gle/zmR5SAeKiJvXpg5Z7
