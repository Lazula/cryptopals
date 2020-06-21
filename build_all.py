#!/usr/bin/python3

import os, subprocess

def get_problem_dirs(current_dir):
    all_top_dirs = os.listdir()
    set_dirs = []
    for i in all_top_dirs:
        if i.startswith('Set '):
            set_dirs.append(i)
    set_dirs = sorted(set_dirs)

    all_problem_dirs = []
    for i in set_dirs:
        for j in os.listdir(i):
            all_problem_dirs.append(current_dir + '/' + i + '/' +  j)

    return sorted(all_problem_dirs)


def main():
    current_dir = os.path.abspath(os.path.curdir)
    dirs = get_problem_dirs(current_dir)
    for i in dirs:
        os.chdir(i)
        print("Running Makefile in {}".format(i))
        subprocess.call(["make"])

if(__name__ == "__main__"):
    main()
