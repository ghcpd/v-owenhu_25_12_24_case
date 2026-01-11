import importlib.util, os
spec = importlib.util.spec_from_file_location('input', r'd:\Bug Bash\API\case_25_12_24\case2\v-owenhu_25_12_24_case\input.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cfgdir = os.path.join(os.path.dirname(mod.__file__), 'configs')
os.makedirs(cfgdir, exist_ok=True)
with open(os.path.join(cfgdir, 'danger.yaml'), 'w', encoding='utf-8') as f:
    f.write('api_key: SECRET_VALUE\nnormal: ok\n')
print('CONFIG_DIR resolved to:', mod.CONFIG_DIR)
print('update_records output:', mod.update_records('danger.yaml'))
