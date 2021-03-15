#pragma once

#include <string>
#include <memory>
#include <vector>
#include <algorithm>


class InputParams
{
public:

	InputParams(int count, char** args)
	{
		for (int i = 1; i < count; i++)
		{
			mParams.push_back(std::string(args[i]));
		}
	}

public:

	bool isSet(const std::string& param) const
	{
		return (std::find(mParams.begin(), mParams.end(), param) != mParams.end());
	}

	const std::string get(const std::string& param) const
	{
		auto paramKey = std::find(mParams.begin(), mParams.end(), param);
		if (paramKey != mParams.end() && ++paramKey != mParams.end())
		{
			return *paramKey;
		}
		else
		{
			return "";
		}
	}


private:

	std::vector<std::string>                 mParams;

};

