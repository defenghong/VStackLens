"""Medium-specific reference projection from one canonical document.

Only unused reference variants are removed. Inspection facts, object rows,
ordering, counts, grades, advice and source evidence are never filtered here.
"""
from copy import deepcopy


def document_for_medium(document,medium):
    if medium not in ('pdf','word','html'):
        raise ValueError('Unknown report medium')
    output=deepcopy(document)
    seen=set()
    def visit(node):
        if isinstance(node,dict):
            if id(node) in seen:return
            seen.add(id(node))
            variants=node.pop('references',None)
            if variants is not None:
                selected=variants[medium]
                if isinstance(selected,str):node['reference']=selected
                else:
                    for key,value in selected.items():
                        if key in node:node[key]=deepcopy(value)
            for value in node.values():visit(value)
        elif isinstance(node,list):
            for value in node:visit(value)
    visit(output)
    return output
