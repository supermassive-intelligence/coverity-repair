import masint
import constants as constval

masint.api_url = constval.SMI_API_URL

count = 9
def get_dataset():
    dataset = []

    for i in range(count):
        dataset.append(
            {"input": f"What is {i} + {i}", "output": "The answer is " + str(i + i)}
        )

    return dataset

llm = masint.SupermassiveIntelligence()

dataset = get_dataset()

status = llm.train(dataset, train_args={"max_steps": (100*count)})

print(status)