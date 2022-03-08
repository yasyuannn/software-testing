import angr
import claripy

def main():
    project = angr.Project("./give_me_password", load_options={"auto_load_libs": False})
    bvs = claripy.BVS('stdin', 100*8)
    initial_state = project.factory.entry_state(stdin = bvs)
    sm = project.factory.simulation_manager(initial_state)
    sm.explore(find=0x4009de)
    found = sm.found[0]
    solution = found.solver.eval(bvs, cast_to=bytes)
    solution = solution[:solution.find(b'\x00')]
    print(solution)
    
    return solution

if __name__ == '__main__':
    print(repr(main()))
